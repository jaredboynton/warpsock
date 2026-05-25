use boring::ssl::SslAcceptor;
use bytes::{Bytes, BytesMut};
use specter::transport::h2::HpackDecoder;
use std::future::Future;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Mutex};
use tokio::time::timeout;

const TEST_IO_TIMEOUT: Duration = Duration::from_secs(1);

/// A mock HTTP/2 server for testing edge cases and protocol violations.
/// Allows scripting specific frame sequences to test client robustness.
#[allow(dead_code)]
pub struct MockH2Server {
    listener: TcpListener,
    port: u16,
}

impl MockH2Server {
    /// Create a new mock H2 server bound to a random port.
    #[allow(dead_code)]
    pub async fn new() -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        Ok(Self { listener, port })
    }

    /// Get the base URL for this server.
    #[allow(dead_code)]
    pub fn url(&self) -> String {
        format!("https://127.0.0.1:{}", self.port)
    }

    /// Get the base URL for this server (HTTPS).
    #[allow(dead_code)]
    pub fn url_tls(&self) -> String {
        format!("https://127.0.0.1:{}", self.port)
    }

    /// Get the port this server is listening on.
    #[allow(dead_code)]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Start the server with a custom handler function.
    /// The handler receives the connection and can send/receive raw frames.
    #[allow(dead_code)]
    pub fn start<F, Fut>(self, handler: F) -> tokio::task::JoinHandle<()>
    where
        F: Fn(MockH2Connection) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let handler = Arc::new(handler);
        tokio::spawn(async move {
            while let Ok((stream, _)) = self.listener.accept().await {
                let handler_clone = Arc::clone(&handler);
                tokio::spawn(async move {
                    let conn = MockH2Connection::new(stream);
                    handler_clone(conn).await;
                });
            }
        })
    }

    /// Start the server and signal once the spawned task reaches the accept loop.
    #[allow(dead_code)]
    pub fn start_with_ready<F, Fut>(
        self,
        handler: F,
    ) -> (tokio::task::JoinHandle<()>, oneshot::Receiver<()>)
    where
        F: Fn(MockH2Connection) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let handler = Arc::new(handler);
        let (ready_tx, ready_rx) = oneshot::channel();
        let handle = tokio::spawn(async move {
            let mut ready_tx = Some(ready_tx);
            loop {
                if let Some(tx) = ready_tx.take() {
                    let _ = tx.send(());
                }
                let Ok((stream, _)) = self.listener.accept().await else {
                    break;
                };
                let handler_clone = Arc::clone(&handler);
                tokio::spawn(async move {
                    let conn = MockH2Connection::new(stream);
                    handler_clone(conn).await;
                });
            }
        });

        (handle, ready_rx)
    }

    /// Start the server with TLS support.
    #[allow(dead_code)]
    pub fn start_tls<F, Fut>(self, acceptor: SslAcceptor, handler: F) -> tokio::task::JoinHandle<()>
    where
        F: Fn(MockH2Connection) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let handler = Arc::new(handler);
        let acceptor = Arc::new(acceptor);

        tokio::spawn(async move {
            while let Ok((stream, _)) = self.listener.accept().await {
                let handler_clone = Arc::clone(&handler);
                let acceptor_clone = acceptor.clone();
                tokio::spawn(async move {
                    match timeout(
                        TEST_IO_TIMEOUT,
                        tokio_boring::accept(&acceptor_clone, stream),
                    )
                    .await
                    {
                        Ok(Ok(tls_stream)) => {
                            let conn = MockH2Connection::new(tls_stream);
                            handler_clone(conn).await;
                        }
                        Ok(Err(_)) | Err(_) => {
                            // Handshake failure or expected error
                        }
                    }
                });
            }
        })
    }
}

/// Represents a single HTTP/2 connection for frame-level control.
#[allow(dead_code)]
pub struct MockH2Connection {
    // Boxed stream to allow TcpStream or TlsStream
    stream: Arc<Mutex<Box<dyn AsyncReadWrite + Send>>>,
    #[allow(dead_code)]
    buffer: Arc<Mutex<BytesMut>>,
}

/// A decoded HEADERS frame received by the mock server.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct DecodedHeadersFrame {
    pub flags: u8,
    pub stream_id: u32,
    pub headers: Vec<(String, String)>,
}

#[allow(dead_code)]
impl DecodedHeadersFrame {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub fn has_header(&self, name: &str) -> bool {
        self.header(name).is_some()
    }

    pub fn assert_rfc8441_websocket_connect(&self, authority: &str, scheme: &str, path: &str) {
        assert_eq!(self.header(":method"), Some("CONNECT"));
        assert_eq!(self.header(":protocol"), Some("websocket"));
        assert_eq!(self.header(":scheme"), Some(scheme));
        assert_eq!(self.header(":path"), Some(path));
        assert_eq!(self.header(":authority"), Some(authority));

        for forbidden in [
            "connection",
            "upgrade",
            "host",
            "sec-websocket-key",
            "sec-websocket-accept",
        ] {
            assert!(
                !self.has_header(forbidden),
                "RFC 8441 CONNECT must not include {forbidden:?}; decoded headers: {:?}",
                self.headers
            );
        }
    }
}

// Helper trait for Box
trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin {}
impl<T: AsyncRead + AsyncWrite + Unpin> AsyncReadWrite for T {}

async fn io_timeout<T, Fut>(future: Fut) -> io::Result<T>
where
    Fut: Future<Output = io::Result<T>>,
{
    timeout(TEST_IO_TIMEOUT, future)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "mock H2 helper I/O timed out"))?
}

impl MockH2Connection {
    fn new<S>(stream: S) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self {
            stream: Arc::new(Mutex::new(Box::new(stream))),
            buffer: Arc::new(Mutex::new(BytesMut::with_capacity(8192))),
        }
    }

    /// Read the HTTP/2 connection preface (24 bytes).
    #[allow(dead_code)]
    pub async fn read_preface(&self) -> std::io::Result<()> {
        let mut stream = self.stream.lock().await;
        let mut preface = [0u8; 24];
        io_timeout(stream.read_exact(&mut preface)).await?;

        const EXPECTED_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        if preface.as_slice() != EXPECTED_PREFACE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid HTTP/2 preface",
            ));
        }
        Ok(())
    }

    /// Read a single frame header (9 bytes) and return (length, type, flags, stream_id).
    pub async fn read_frame_header(&self) -> std::io::Result<(u32, u8, u8, u32)> {
        let mut stream = self.stream.lock().await;
        let mut header = [0u8; 9];
        io_timeout(stream.read_exact(&mut header)).await?;

        let length = u32::from_be_bytes([0, header[0], header[1], header[2]]);
        let frame_type = header[3];
        let flags = header[4];
        let stream_id = u32::from_be_bytes([
            header[5] & 0x7F, // Clear reserved bit
            header[6],
            header[7],
            header[8],
        ]);

        Ok((length, frame_type, flags, stream_id))
    }

    /// Read frame payload of given length.
    #[allow(dead_code)]
    pub async fn read_payload(&self, length: u32) -> std::io::Result<Bytes> {
        let mut stream = self.stream.lock().await;
        let mut payload = vec![0u8; length as usize];
        io_timeout(stream.read_exact(&mut payload)).await?;
        Ok(Bytes::from(payload))
    }

    /// Read the next complete frame from the client.
    #[allow(dead_code)]
    pub async fn read_frame(&self) -> std::io::Result<(u32, u8, u8, u32, Bytes)> {
        let (length, frame_type, flags, stream_id) = self.read_frame_header().await?;
        let payload = if length > 0 {
            self.read_payload(length).await?
        } else {
            Bytes::new()
        };
        Ok((length, frame_type, flags, stream_id, payload))
    }

    /// Read the next HEADERS frame and HPACK-decode its header block.
    #[allow(dead_code)]
    pub async fn read_decoded_headers(&self) -> std::io::Result<DecodedHeadersFrame> {
        let (flags, stream_id, payload) = loop {
            let (_, frame_type, flags, stream_id, payload) = self.read_frame().await?;
            if frame_type == 0x01 {
                break (flags, stream_id, payload);
            }

            if matches!(frame_type, 0x04 | 0x08 | 0x02) {
                continue;
            }

            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("expected HEADERS frame, got type {frame_type:#04x}"),
            ));
        };

        let mut decoder = HpackDecoder::new();
        let headers = decoder.decode(&payload).map_err(|err| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to decode HPACK header block: {err}"),
            )
        })?;

        Ok(DecodedHeadersFrame {
            flags,
            stream_id,
            headers,
        })
    }

    /// Send a raw frame to the client.
    pub async fn send_frame(
        &self,
        frame_type: u8,
        flags: u8,
        stream_id: u32,
        payload: &[u8],
    ) -> std::io::Result<()> {
        let mut stream = self.stream.lock().await;

        let length = payload.len() as u32;
        let mut frame = Vec::with_capacity(9 + payload.len());

        // Write 24-bit length
        frame.extend_from_slice(&[
            ((length >> 16) & 0xFF) as u8,
            ((length >> 8) & 0xFF) as u8,
            (length & 0xFF) as u8,
        ]);
        frame.push(frame_type);
        frame.push(flags);

        // Write 32-bit stream ID (clear reserved bit)
        frame.extend_from_slice(&(stream_id & 0x7FFFFFFF).to_be_bytes());

        frame.extend_from_slice(payload);

        io_timeout(stream.write_all(&frame)).await?;
        io_timeout(stream.flush()).await
    }

    /// Send SETTINGS frame (frame type 0x04).
    #[allow(dead_code)]
    pub async fn send_settings(&self, settings: &[(u16, u32)]) -> std::io::Result<()> {
        let mut payload = Vec::new();
        for (id, value) in settings {
            payload.extend_from_slice(&id.to_be_bytes());
            payload.extend_from_slice(&value.to_be_bytes());
        }
        self.send_frame(0x04, 0x00, 0, &payload).await
    }

    /// Send SETTINGS ACK.
    #[allow(dead_code)]
    pub async fn send_settings_ack(&self) -> std::io::Result<()> {
        self.send_frame(0x04, 0x01, 0, &[]).await
    }

    /// Send WINDOW_UPDATE frame (frame type 0x08).
    #[allow(dead_code)]
    pub async fn send_window_update(&self, stream_id: u32, increment: u32) -> std::io::Result<()> {
        let payload = (increment & 0x7FFFFFFF).to_be_bytes();
        self.send_frame(0x08, 0x00, stream_id, &payload).await
    }

    /// Send HEADERS frame (frame type 0x01).
    #[allow(dead_code)]
    pub async fn send_headers(
        &self,
        stream_id: u32,
        headers: &[u8],
        end_stream: bool,
        end_headers: bool,
    ) -> std::io::Result<()> {
        let mut flags = 0u8;
        if end_stream {
            flags |= 0x01;
        }
        if end_headers {
            flags |= 0x04;
        }
        self.send_frame(0x01, flags, stream_id, headers).await
    }

    /// Send DATA frame (frame type 0x00).
    #[allow(dead_code)]
    pub async fn send_data(
        &self,
        stream_id: u32,
        data: &[u8],
        end_stream: bool,
    ) -> std::io::Result<()> {
        let flags = if end_stream { 0x01 } else { 0x00 };
        self.send_frame(0x00, flags, stream_id, data).await
    }

    /// Send RST_STREAM frame (frame type 0x03).
    #[allow(dead_code)]
    pub async fn send_rst_stream(&self, stream_id: u32, error_code: u32) -> std::io::Result<()> {
        let payload = error_code.to_be_bytes();
        self.send_frame(0x03, 0x00, stream_id, &payload).await
    }

    /// Send GOAWAY frame (frame type 0x07).
    #[allow(dead_code)]
    pub async fn send_goaway(&self, last_stream_id: u32, error_code: u32) -> std::io::Result<()> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&(last_stream_id & 0x7FFFFFFF).to_be_bytes());
        payload.extend_from_slice(&error_code.to_be_bytes());
        self.send_frame(0x07, 0x00, 0, &payload).await
    }

    /// Send PUSH_PROMISE frame (frame type 0x05).
    #[allow(dead_code)]
    pub async fn send_push_promise(
        &self,
        stream_id: u32,
        promised_stream_id: u32,
        headers: &[u8],
    ) -> std::io::Result<()> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&(promised_stream_id & 0x7FFFFFFF).to_be_bytes());
        payload.extend_from_slice(headers);
        self.send_frame(0x05, 0x04, stream_id, &payload).await // END_HEADERS flag
    }
}
