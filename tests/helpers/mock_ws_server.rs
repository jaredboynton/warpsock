#![allow(dead_code)]

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use boring::sha::sha1;
use boring::ssl::SslAcceptor;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

#[derive(Debug, Clone)]
pub struct WsRequest {
    pub request_line: String,
    pub headers: Vec<(String, String)>,
}

impl WsRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub fn sec_websocket_key_len(&self) -> usize {
        self.header("Sec-WebSocket-Key")
            .and_then(|value| BASE64.decode(value.trim()).ok())
            .map(|decoded| decoded.len())
            .unwrap_or(0)
    }
}

#[derive(Debug, Clone)]
pub struct CapturedFrame {
    pub fin: bool,
    pub opcode: u8,
    pub masked: bool,
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub struct WsExchange {
    pub request: WsRequest,
    pub client_frame: Option<CapturedFrame>,
    pub selected_alpn: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct WsResponse {
    pub status_line: String,
    pub accept: AcceptMode,
    pub headers: Vec<(String, String)>,
    pub first_frame: Option<Vec<u8>>,
}

impl Default for WsResponse {
    fn default() -> Self {
        Self {
            status_line: "HTTP/1.1 101 Switching Protocols".to_string(),
            accept: AcceptMode::Valid,
            headers: Vec::new(),
            first_frame: None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum AcceptMode {
    Valid,
    Wrong,
    Omit,
}

pub struct MockWsServer {
    listener: TcpListener,
    port: u16,
}

impl MockWsServer {
    pub async fn new() -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        Ok(Self { listener, port })
    }

    pub fn ws_url(&self, path: &str) -> String {
        format!("ws://127.0.0.1:{}{}", self.port, path)
    }

    pub fn wss_url(&self, path: &str) -> String {
        format!("wss://127.0.0.1:{}{}", self.port, path)
    }

    pub fn start_once(self, response: WsResponse) -> tokio::task::JoinHandle<WsExchange> {
        tokio::spawn(async move {
            let (stream, _) = self
                .listener
                .accept()
                .await
                .expect("accept websocket client");
            handle_ws_connection(stream, response, None).await
        })
    }

    pub fn start_tls_once(
        self,
        acceptor: SslAcceptor,
        response: WsResponse,
    ) -> tokio::task::JoinHandle<WsExchange> {
        tokio::spawn(async move {
            let (stream, _) = self
                .listener
                .accept()
                .await
                .expect("accept websocket client");
            let mut tls_stream = tokio_boring::accept(&acceptor, stream)
                .await
                .expect("accept websocket TLS client");
            let selected_alpn = tls_stream
                .ssl()
                .selected_alpn_protocol()
                .map(|protocol| protocol.to_vec());
            handle_ws_connection(&mut tls_stream, response, selected_alpn).await
        })
    }
}

async fn handle_ws_connection<S>(
    mut stream: S,
    response: WsResponse,
    selected_alpn: Option<Vec<u8>>,
) -> WsExchange
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request_bytes = read_until_headers(&mut stream).await;
    let request = parse_request(&request_bytes);

    let mut response_bytes = Vec::new();
    response_bytes.extend_from_slice(response.status_line.as_bytes());
    response_bytes.extend_from_slice(b"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n");

    match response.accept {
        AcceptMode::Valid => {
            let key = request
                .header("Sec-WebSocket-Key")
                .expect("request contains Sec-WebSocket-Key");
            response_bytes.extend_from_slice(
                format!("Sec-WebSocket-Accept: {}\r\n", websocket_accept(key)).as_bytes(),
            );
        }
        AcceptMode::Wrong => {
            response_bytes.extend_from_slice(b"Sec-WebSocket-Accept: definitely-wrong\r\n");
        }
        AcceptMode::Omit => {}
    }

    for (name, value) in response.headers {
        response_bytes.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }

    response_bytes.extend_from_slice(b"\r\n");
    if let Some(frame) = response.first_frame {
        response_bytes.extend_from_slice(&frame);
    }

    stream
        .write_all(&response_bytes)
        .await
        .expect("write websocket handshake response");
    stream.flush().await.expect("flush websocket response");

    let client_frame = timeout(Duration::from_millis(500), read_frame(&mut stream))
        .await
        .ok()
        .and_then(Result::ok);

    WsExchange {
        request,
        client_frame,
        selected_alpn,
    }
}

pub fn websocket_accept(key: &str) -> String {
    let mut input = Vec::with_capacity(key.len() + WS_GUID.len());
    input.extend_from_slice(key.trim().as_bytes());
    input.extend_from_slice(WS_GUID.as_bytes());
    BASE64.encode(sha1(&input))
}

pub fn server_text_frame(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    assert!(bytes.len() <= 125, "test helper only supports small frames");

    let mut frame = Vec::with_capacity(2 + bytes.len());
    frame.push(0x81);
    frame.push(bytes.len() as u8);
    frame.extend_from_slice(bytes);
    frame
}

pub fn server_ping_frame(payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() <= 125, "control frame payload too large");

    let mut frame = Vec::with_capacity(2 + payload.len());
    frame.push(0x89);
    frame.push(payload.len() as u8);
    frame.extend_from_slice(payload);
    frame
}

async fn read_until_headers<S>(stream: &mut S) -> Vec<u8>
where
    S: AsyncRead + Unpin,
{
    let mut bytes = Vec::new();
    let mut buf = [0u8; 1024];

    loop {
        let n = timeout(Duration::from_secs(2), stream.read(&mut buf))
            .await
            .expect("timed out reading request")
            .expect("read request");
        assert_ne!(n, 0, "client closed before request headers completed");

        bytes.extend_from_slice(&buf[..n]);
        if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
            return bytes;
        }
    }
}

fn parse_request(bytes: &[u8]) -> WsRequest {
    let raw = std::str::from_utf8(bytes).expect("websocket handshake is utf-8 HTTP");
    let (head, _) = raw.split_once("\r\n\r\n").expect("complete HTTP headers");
    let mut lines = head.split("\r\n");
    let request_line = lines.next().expect("request line").to_string();
    let headers = lines
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_string(), value.trim().to_string()))
        })
        .collect();

    WsRequest {
        request_line,
        headers,
    }
}

async fn read_frame<S>(stream: &mut S) -> std::io::Result<CapturedFrame>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;

    let fin = header[0] & 0x80 != 0;
    let opcode = header[0] & 0x0f;
    let masked = header[1] & 0x80 != 0;
    let mut len = (header[1] & 0x7f) as u64;

    if len == 126 {
        let mut ext = [0u8; 2];
        stream.read_exact(&mut ext).await?;
        len = u16::from_be_bytes(ext) as u64;
    } else if len == 127 {
        let mut ext = [0u8; 8];
        stream.read_exact(&mut ext).await?;
        len = u64::from_be_bytes(ext);
    }

    let mask = if masked {
        let mut key = [0u8; 4];
        stream.read_exact(&mut key).await?;
        Some(key)
    } else {
        None
    };

    let mut payload = vec![0u8; len as usize];
    stream.read_exact(&mut payload).await?;

    if let Some(mask) = mask {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
    }

    Ok(CapturedFrame {
        fin,
        opcode,
        masked,
        payload,
    })
}
