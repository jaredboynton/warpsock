use bytes::Bytes;
use specter::{Client, HttpVersion};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration, Instant};

#[derive(Clone, Debug)]
struct RequestLog {
    connection_id: usize,
    path: String,
    cookie_header: Option<String>,
}

struct H1Fixture {
    url: String,
    logs: Arc<Mutex<Vec<RequestLog>>>,
}

impl H1Fixture {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let logs = Arc::new(Mutex::new(Vec::new()));
        let next_id = Arc::new(AtomicUsize::new(1));
        let logs_for_task = logs.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let id = next_id.fetch_add(1, Ordering::SeqCst);
                let logs = logs_for_task.clone();
                tokio::spawn(handle_connection(id, stream, logs));
            }
        });
        Self { url, logs }
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}{}", self.url, path)
    }

    async fn logs(&self) -> Vec<RequestLog> {
        self.logs.lock().await.clone()
    }
}

async fn handle_connection(id: usize, mut stream: TcpStream, logs: Arc<Mutex<Vec<RequestLog>>>) {
    let mut buffer = Vec::new();
    loop {
        let mut read_buf = [0u8; 1024];
        while !buffer.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = match stream.read(&mut read_buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            buffer.extend_from_slice(&read_buf[..n]);
        }

        let header_end = buffer.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let request = String::from_utf8_lossy(&buffer[..header_end]);
        let path = request
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap_or("/")
            .to_string();
        let cookie_header = request
            .lines()
            .find(|line| line.to_ascii_lowercase().starts_with("cookie:"))
            .map(|line| {
                let parts: Vec<&str> = line.splitn(2, ':').collect();
                if parts.len() == 2 {
                    parts[1].trim().to_string()
                } else {
                    "".to_string()
                }
            });

        buffer.drain(..header_end);
        logs.lock().await.push(RequestLog {
            connection_id: id,
            path: path.clone(),
            cookie_header,
        });

        match path.as_str() {
            "/compressed" => {
                let body = b"hello compressed";
                let mut encoder =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                use std::io::Write;
                encoder.write_all(body).unwrap();
                let compressed = encoder.finish().unwrap();
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                            compressed.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
                stream.write_all(&compressed).await.unwrap();
                stream.flush().await.unwrap();
            }
            "/cookie" => {
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nSet-Cookie: test_cookie=cookie_val; Path=/\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok",
                    )
                    .await
                    .unwrap();
                stream.flush().await.unwrap();
            }
            "/delay-headers" => {
                tokio::time::sleep(Duration::from_millis(150)).await;
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok",
                    )
                    .await
                    .unwrap();
                stream.flush().await.unwrap();
            }
            "/delay-chunks" => {
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n")
                    .await
                    .unwrap();
                stream.flush().await.unwrap();
                stream.write_all(b"5\r\nfirst\r\n").await.unwrap();
                stream.flush().await.unwrap();
                tokio::time::sleep(Duration::from_millis(150)).await;
                stream.write_all(b"0\r\n\r\n").await.unwrap();
                stream.flush().await.unwrap();
            }
            "/fixed" | "/dispatch" => {
                write_fixed(&mut stream, &[b"one-", b"two-", b"three"]).await;
            }
            "/chunked" => {
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n")
                    .await
                    .unwrap();
                for chunk in [b"alpha-" as &[u8], b"beta-", b"gamma"] {
                    stream
                        .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                        .await
                        .unwrap();
                    stream.write_all(chunk).await.unwrap();
                    stream.write_all(b"\r\n").await.unwrap();
                    stream.flush().await.unwrap();
                    tokio::time::sleep(Duration::from_millis(30)).await;
                }
                stream.write_all(b"0\r\n\r\n").await.unwrap();
                stream.flush().await.unwrap();
            }
            "/close" => {
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nclose-")
                    .await
                    .unwrap();
                stream.flush().await.unwrap();
                tokio::time::sleep(Duration::from_millis(30)).await;
                stream.write_all(b"delimited").await.unwrap();
                stream.flush().await.unwrap();
                return;
            }
            "/unfinished" => {
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nearly-1")
                    .await
                    .unwrap();
                stream.flush().await.unwrap();
                tokio::time::sleep(Duration::from_millis(30)).await;
                stream.write_all(b"early-2").await.unwrap();
                stream.flush().await.unwrap();
                tokio::time::sleep(Duration::from_secs(60)).await;
                return;
            }
            _ => write_fixed(&mut stream, &[b"ok"]).await,
        }
    }
}

async fn write_fixed(stream: &mut TcpStream, chunks: &[&[u8]]) {
    let len: usize = chunks.iter().map(|c| c.len()).sum();
    stream
        .write_all(
            format!("HTTP/1.1 200 OK\r\nContent-Length: {len}\r\nConnection: keep-alive\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    stream.flush().await.unwrap();
    for chunk in chunks {
        tokio::time::sleep(Duration::from_millis(30)).await;
        stream.write_all(chunk).await.unwrap();
        stream.flush().await.unwrap();
    }
}

async fn collect(mut response: specter::Response) -> Vec<u8> {
    let mut body = Vec::new();
    while let Some(frame) = response.body_mut().frame().await {
        let data = frame.unwrap().into_data().unwrap();
        body.extend_from_slice(&data);
    }
    body
}

async fn next_data(body: &mut specter::Body) -> Bytes {
    let frame = body.frame().await.unwrap().unwrap();
    frame.into_data().unwrap()
}

#[tokio::test]
async fn h1_high_level_send_streaming_dispatches_to_h1() {
    let fixture = H1Fixture::start().await;
    let client = Client::builder().prefer_http2(false).build().unwrap();

    let started = Instant::now();
    let response = client
        .get(fixture.endpoint("/dispatch"))
        .version(HttpVersion::Http1_1)
        .send_streaming()
        .await
        .unwrap();

    assert_eq!(response.http_version(), "HTTP/1.1");
    assert!(started.elapsed() < Duration::from_millis(25));
    assert_eq!(collect(response).await, b"one-two-three");
    assert_eq!(fixture.logs().await[0].path, "/dispatch");
}

#[tokio::test]
async fn h1_streams_fixed_content_length_incrementally() {
    let fixture = H1Fixture::start().await;
    let client = Client::builder().prefer_http2(false).build().unwrap();
    let mut response = client
        .get(fixture.endpoint("/fixed"))
        .version(HttpVersion::Http1_1)
        .send_streaming()
        .await
        .unwrap();

    let first = timeout(Duration::from_millis(80), response.body_mut().frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert_eq!(first, Bytes::from_static(b"one-"));
    let mut body = first.to_vec();
    while let Some(frame) = response.body_mut().frame().await {
        let chunk = frame.unwrap().into_data().unwrap();
        body.extend_from_slice(&chunk);
    }
    assert_eq!(body, b"one-two-three");
}

#[tokio::test]
async fn h1_streams_chunked_transfer_incrementally() {
    let fixture = H1Fixture::start().await;
    let client = Client::builder().prefer_http2(false).build().unwrap();
    let mut response = client
        .get(fixture.endpoint("/chunked"))
        .version(HttpVersion::Http1_1)
        .send_streaming()
        .await
        .unwrap();

    let first = timeout(Duration::from_millis(80), response.body_mut().frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert_eq!(first, Bytes::from_static(b"alpha-"));
    let mut body = first.to_vec();
    while let Some(frame) = response.body_mut().frame().await {
        let chunk = frame.unwrap().into_data().unwrap();
        body.extend_from_slice(&chunk);
    }
    assert_eq!(body, b"alpha-beta-gamma");

    let response = client
        .get(fixture.endpoint("/fixed"))
        .version(HttpVersion::Http1_1)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.bytes_raw().unwrap(),
        Bytes::from_static(b"one-two-three")
    );
}

#[tokio::test]
async fn h1_streams_close_delimited_without_reuse() {
    let fixture = H1Fixture::start().await;
    let client = Client::builder().prefer_http2(false).build().unwrap();
    let response = client
        .get(fixture.endpoint("/close"))
        .version(HttpVersion::Http1_1)
        .send_streaming()
        .await
        .unwrap();
    assert_eq!(collect(response).await, b"close-delimited");

    let response = client
        .get(fixture.endpoint("/fixed"))
        .version(HttpVersion::Http1_1)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.bytes_raw().unwrap(),
        Bytes::from_static(b"one-two-three")
    );
    let logs = fixture.logs().await;
    assert_ne!(logs[0].connection_id, logs[1].connection_id);
}

#[tokio::test]
async fn h1_does_not_buffer_unfinished_stream() {
    let fixture = H1Fixture::start().await;
    let client = Client::builder().prefer_http2(false).build().unwrap();
    let mut response = client
        .get(fixture.endpoint("/unfinished"))
        .version(HttpVersion::Http1_1)
        .send_streaming()
        .await
        .unwrap();

    let first = timeout(Duration::from_millis(80), response.body_mut().frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert_eq!(first, Bytes::from_static(b"early-1"));
    let second = timeout(Duration::from_millis(80), response.body_mut().frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert_eq!(second, Bytes::from_static(b"early-2"));
}

#[tokio::test]
async fn h1_streaming_preserves_timeouts_and_cookies() {
    let fixture = H1Fixture::start().await;

    // Cookie Store Test
    let client = Client::builder()
        .prefer_http2(false)
        .cookie_store(true)
        .build()
        .unwrap();

    // 1. Send streaming request to a path that sets a cookie
    let response = client
        .get(fixture.endpoint("/cookie"))
        .version(HttpVersion::Http1_1)
        .send_streaming()
        .await
        .unwrap();

    // Consume body to complete/drain
    assert_eq!(collect(response).await, b"ok");

    // 2. Send subsequent request to "/ok" and verify cookie is replayed
    let _response2 = client
        .get(fixture.endpoint("/ok"))
        .version(HttpVersion::Http1_1)
        .send_streaming()
        .await
        .unwrap();

    let logs = fixture.logs().await;
    // We should have logs for both requests. The second one should contain the cookie.
    let second_log = logs
        .iter()
        .find(|log| log.path == "/ok")
        .expect("Second request log not found");
    assert_eq!(
        second_log.cookie_header.as_deref(),
        Some("test_cookie=cookie_val")
    );

    // Timeout Tests
    // 3. TTFB timeout
    let ttfb_client = Client::builder()
        .prefer_http2(false)
        .ttfb_timeout(Duration::from_millis(50))
        .build()
        .unwrap();

    let res = ttfb_client
        .get(fixture.endpoint("/delay-headers"))
        .version(HttpVersion::Http1_1)
        .send_streaming()
        .await;

    assert!(res.is_err());
    let err = res.err().unwrap();
    assert!(
        matches!(err, specter::Error::TtfbTimeout(_)),
        "Expected TtfbTimeout, got {:?}",
        err
    );

    // 4. Read Idle timeout
    let idle_client = Client::builder()
        .prefer_http2(false)
        .read_timeout(Duration::from_millis(50))
        .build()
        .unwrap();

    let mut response3 = idle_client
        .get(fixture.endpoint("/delay-chunks"))
        .version(HttpVersion::Http1_1)
        .send_streaming()
        .await
        .unwrap();

    // First chunk should arrive fine
    let first_chunk = next_data(response3.body_mut()).await;
    assert_eq!(first_chunk, Bytes::from_static(b"first"));

    // Second chunk should hit ReadIdleTimeout
    let res_next = response3.body_mut().frame().await;
    assert!(res_next.is_some());
    let err_next = res_next.unwrap();
    assert!(err_next.is_err());
    let err = err_next.err().unwrap();
    assert!(
        matches!(err, specter::Error::ReadIdleTimeout(_)),
        "Expected ReadIdleTimeout, got {:?}",
        err
    );
}

#[tokio::test]
async fn h1_compressed_streaming_decodes_incrementally() {
    let fixture = H1Fixture::start().await;
    let client = Client::builder().prefer_http2(false).build().unwrap();

    let res = client
        .get(fixture.endpoint("/compressed"))
        .version(HttpVersion::Http1_1)
        .send_streaming()
        .await;

    assert!(res.is_err());
    let err = res.err().unwrap();
    assert!(
        matches!(err, specter::Error::Decompression(_)),
        "Expected Decompression error, got {:?}",
        err
    );
}
