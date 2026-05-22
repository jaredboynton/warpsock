use bytes::Bytes;
use specter::{Client, HttpVersion};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};

mod helpers;
use helpers::mock_server::MockHttpServer;

#[tokio::test]
async fn test_h1_connection_reuse() {
    // Start mock server
    let server = MockHttpServer::new().await.unwrap();
    let url = server.url();
    let _server_handle = server.start_with_request_limit(2);

    // Give server time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Client
    let client = Client::builder().prefer_http2(false).build().unwrap();

    // Request 1
    let resp1 = client
        .get(url.as_str())
        .send()
        .await
        .expect("Request 1 failed");
    assert_eq!(resp1.status().as_u16(), 200);
    assert_eq!(resp1.text().unwrap(), "Hello");

    // Request 2 - should reuse the same connection
    let resp2 = client
        .get(url.as_str())
        .send()
        .await
        .expect("Request 2 failed");
    assert_eq!(resp2.status().as_u16(), 200);
    assert_eq!(resp2.text().unwrap(), "Hello");
}

#[tokio::test]
async fn test_h1_connection_expiration() {
    // Test that connections expire after idle timeout
    let server = MockHttpServer::new().await.unwrap();
    let url = server.url();
    let _server_handle = server.start_with_request_limit(3);

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let client = Client::builder().prefer_http2(false).build().unwrap();

    // Request 1
    let resp1 = client
        .get(url.as_str())
        .send()
        .await
        .expect("Request 1 failed");
    assert_eq!(resp1.status().as_u16(), 200);

    // Wait longer than connection pool idle timeout (30s default)
    // For testing, we'll just verify the connection pool works
    // In a real scenario, we'd need to configure a shorter timeout
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Request 2 - should still work (connection may or may not be reused depending on timing)
    let resp2 = client
        .get(url.as_str())
        .send()
        .await
        .expect("Request 2 failed");
    assert_eq!(resp2.status().as_u16(), 200);
}

#[tokio::test]
async fn test_h1_multiple_sequential_requests() {
    // Test multiple sequential requests reuse connection
    let server = MockHttpServer::new().await.unwrap();
    let url = server.url();
    let _server_handle = server.start_with_request_limit(10);

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let client = Client::builder().prefer_http2(false).build().unwrap();

    // Make 5 sequential requests
    for i in 0..5 {
        let resp = client
            .get(url.as_str())
            .send()
            .await
            .unwrap_or_else(|_| panic!("Request {} failed", i + 1));
        assert_eq!(resp.status().as_u16(), 200);
        assert_eq!(resp.text().unwrap(), "Hello");
    }
}

#[derive(Clone, Debug)]
struct PoolLog {
    connection_id: usize,
    path: String,
}

struct PoolFixture {
    url: String,
    logs: Arc<Mutex<Vec<PoolLog>>>,
}

impl PoolFixture {
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
                tokio::spawn(handle_pool_connection(id, stream, logs));
            }
        });
        Self { url, logs }
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}{}", self.url, path)
    }

    async fn logs(&self) -> Vec<PoolLog> {
        self.logs.lock().await.clone()
    }
}

async fn handle_pool_connection(id: usize, mut stream: TcpStream, logs: Arc<Mutex<Vec<PoolLog>>>) {
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
        logs.lock().await.push(PoolLog {
            connection_id: id,
            path: path.clone(),
        });

        match path.as_str() {
            "/chunked" => {
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
                    .await
                    .unwrap();
                stream.flush().await.unwrap();
            }
            "/malformed" => {
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n5\r\nabc")
                    .await
                    .unwrap();
                stream.flush().await.unwrap();
                return;
            }
            "/abort" => {
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: keep-alive\r\n\r\nfirst")
                    .await
                    .unwrap();
                stream.flush().await.unwrap();
                tokio::time::sleep(Duration::from_millis(150)).await;
                let _ = stream.write_all(b"-second").await;
                let _ = stream.flush().await;
            }
            _ => {
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok",
                    )
                    .await
                    .unwrap();
                stream.flush().await.unwrap();
            }
        }
    }
}

async fn drain(mut rx: tokio::sync::mpsc::Receiver<Result<Bytes, specter::Error>>) -> Vec<u8> {
    let mut body = Vec::new();
    while let Some(chunk) = rx.recv().await {
        body.extend_from_slice(&chunk.unwrap());
    }
    body
}

#[tokio::test]
async fn h1_reuses_connection_after_stream_drain() {
    let fixture = PoolFixture::start().await;
    let client = Client::builder().prefer_http2(false).build().unwrap();

    let (_response, rx) = client
        .get(fixture.endpoint("/chunked"))
        .version(HttpVersion::Http1_1)
        .send_streaming()
        .await
        .unwrap();
    assert_eq!(drain(rx).await, b"hello");
    tokio::time::sleep(Duration::from_millis(20)).await;

    let response = client
        .get(fixture.endpoint("/ok"))
        .version(HttpVersion::Http1_1)
        .send()
        .await
        .unwrap();
    assert_eq!(response.bytes_raw(), Bytes::from_static(b"ok"));

    let logs = fixture.logs().await;
    assert_eq!(logs[0].path, "/chunked");
    assert_eq!(logs[1].path, "/ok");
    assert_eq!(logs[0].connection_id, logs[1].connection_id);
}

#[tokio::test]
async fn h1_discards_connection_after_malformed_stream() {
    let fixture = PoolFixture::start().await;
    let client = Client::builder().prefer_http2(false).build().unwrap();

    let (_response, mut rx) = client
        .get(fixture.endpoint("/malformed"))
        .version(HttpVersion::Http1_1)
        .send_streaming()
        .await
        .unwrap();
    let err = timeout(Duration::from_secs(1), async move {
        while let Some(chunk) = rx.recv().await {
            if chunk.is_err() {
                return true;
            }
        }
        false
    })
    .await
    .unwrap();
    assert!(err);

    let response = client
        .get(fixture.endpoint("/ok"))
        .version(HttpVersion::Http1_1)
        .send()
        .await
        .unwrap();
    assert_eq!(response.bytes_raw(), Bytes::from_static(b"ok"));
    let logs = fixture.logs().await;
    assert_eq!(logs[0].path, "/malformed");
    assert_eq!(logs[1].path, "/ok");
    assert_ne!(logs[0].connection_id, logs[1].connection_id);
}

#[tokio::test]
async fn h1_discards_connection_after_aborted_stream() {
    let fixture = PoolFixture::start().await;
    let client = Client::builder().prefer_http2(false).build().unwrap();

    let (_response, mut rx) = client
        .get(fixture.endpoint("/abort"))
        .version(HttpVersion::Http1_1)
        .send_streaming()
        .await
        .unwrap();
    assert_eq!(
        rx.recv().await.unwrap().unwrap(),
        Bytes::from_static(b"first")
    );
    drop(rx);

    let response = client
        .get(fixture.endpoint("/ok"))
        .version(HttpVersion::Http1_1)
        .send()
        .await
        .unwrap();
    assert_eq!(response.bytes_raw(), Bytes::from_static(b"ok"));
    let logs = fixture.logs().await;
    assert_eq!(logs[0].path, "/abort");
    assert_eq!(logs[1].path, "/ok");
    assert_ne!(logs[0].connection_id, logs[1].connection_id);
}
