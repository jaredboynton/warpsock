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
        buffer.drain(..header_end);
        logs.lock().await.push(RequestLog {
            connection_id: id,
            path: path.clone(),
        });

        match path.as_str() {
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

async fn collect(mut rx: tokio::sync::mpsc::Receiver<Result<Bytes, specter::Error>>) -> Vec<u8> {
    let mut body = Vec::new();
    while let Some(chunk) = rx.recv().await {
        body.extend_from_slice(&chunk.unwrap());
    }
    body
}

#[tokio::test]
async fn h1_high_level_send_streaming_dispatches_to_h1() {
    let fixture = H1Fixture::start().await;
    let client = Client::builder().prefer_http2(false).build().unwrap();

    let started = Instant::now();
    let (response, rx) = client
        .get(fixture.endpoint("/dispatch"))
        .version(HttpVersion::Http1_1)
        .send_streaming()
        .await
        .unwrap();

    assert_eq!(response.http_version(), "HTTP/1.1");
    assert!(started.elapsed() < Duration::from_millis(25));
    assert_eq!(collect(rx).await, b"one-two-three");
    assert_eq!(fixture.logs().await[0].path, "/dispatch");
}

#[tokio::test]
async fn h1_streams_fixed_content_length_incrementally() {
    let fixture = H1Fixture::start().await;
    let client = Client::builder().prefer_http2(false).build().unwrap();
    let (_response, mut rx) = client
        .get(fixture.endpoint("/fixed"))
        .version(HttpVersion::Http1_1)
        .send_streaming()
        .await
        .unwrap();

    let first = timeout(Duration::from_millis(80), rx.recv())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(first, Bytes::from_static(b"one-"));
    let mut body = first.to_vec();
    while let Some(chunk) = rx.recv().await {
        body.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(body, b"one-two-three");
}

#[tokio::test]
async fn h1_streams_chunked_transfer_incrementally() {
    let fixture = H1Fixture::start().await;
    let client = Client::builder().prefer_http2(false).build().unwrap();
    let (_response, mut rx) = client
        .get(fixture.endpoint("/chunked"))
        .version(HttpVersion::Http1_1)
        .send_streaming()
        .await
        .unwrap();

    let first = timeout(Duration::from_millis(80), rx.recv())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(first, Bytes::from_static(b"alpha-"));
    let mut body = first.to_vec();
    while let Some(chunk) = rx.recv().await {
        body.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(body, b"alpha-beta-gamma");

    let response = client
        .get(fixture.endpoint("/fixed"))
        .version(HttpVersion::Http1_1)
        .send()
        .await
        .unwrap();
    assert_eq!(response.bytes_raw(), Bytes::from_static(b"one-two-three"));
}

#[tokio::test]
async fn h1_streams_close_delimited_without_reuse() {
    let fixture = H1Fixture::start().await;
    let client = Client::builder().prefer_http2(false).build().unwrap();
    let (_response, rx) = client
        .get(fixture.endpoint("/close"))
        .version(HttpVersion::Http1_1)
        .send_streaming()
        .await
        .unwrap();
    assert_eq!(collect(rx).await, b"close-delimited");

    let response = client
        .get(fixture.endpoint("/fixed"))
        .version(HttpVersion::Http1_1)
        .send()
        .await
        .unwrap();
    assert_eq!(response.bytes_raw(), Bytes::from_static(b"one-two-three"));
    let logs = fixture.logs().await;
    assert_ne!(logs[0].connection_id, logs[1].connection_id);
}

#[tokio::test]
async fn h1_does_not_buffer_unfinished_stream() {
    let fixture = H1Fixture::start().await;
    let client = Client::builder().prefer_http2(false).build().unwrap();
    let (_response, mut rx) = client
        .get(fixture.endpoint("/unfinished"))
        .version(HttpVersion::Http1_1)
        .send_streaming()
        .await
        .unwrap();

    let first = timeout(Duration::from_millis(80), rx.recv())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(first, Bytes::from_static(b"early-1"));
    let second = timeout(Duration::from_millis(80), rx.recv())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(second, Bytes::from_static(b"early-2"));
}
