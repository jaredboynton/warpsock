//! Tests proving that reqwest-style `ClientBuilder` knobs (DNS overrides,
//! pool sizing/idle timeout, custom resolver, H3 max idle timeout) actually
//! affect runtime behavior end-to-end via `Client::builder()`.

use specter::transport::dns::{Resolve, ResolveFuture};
use specter::{Client, RequestBody};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

mod helpers;
use helpers::mock_h3_server::{MockEvent, MockH3Server};

#[derive(Clone, Debug)]
struct ConnLog {
    connection_id: usize,
}

struct H1Fixture {
    addr: SocketAddr,
    logs: Arc<Mutex<Vec<ConnLog>>>,
}

impl H1Fixture {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
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

        Self { addr, logs }
    }

    async fn logs(&self) -> Vec<ConnLog> {
        self.logs.lock().await.clone()
    }
}

async fn handle_connection(id: usize, mut stream: TcpStream, logs: Arc<Mutex<Vec<ConnLog>>>) {
    logs.lock().await.push(ConnLog { connection_id: id });

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
        buffer.drain(..header_end);

        if stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok")
            .await
            .is_err()
        {
            return;
        }
        let _ = stream.flush().await;
    }
}

#[tokio::test]
async fn resolve_to_addrs_override_routes_traffic_to_loopback_for_h1() {
    let fixture = H1Fixture::start().await;

    // Use a hostname that does not resolve via the system resolver. The DNS
    // override must redirect it to the loopback fixture.
    let host = "specter-resolve-override.test";
    let url = format!("http://{}:{}/hello", host, fixture.addr.port());

    let client = Client::builder()
        .prefer_http2(false)
        .resolve(host, fixture.addr)
        .build()
        .unwrap();

    let response = client.get(url.as_str()).send().await.expect("request 1");
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.text().unwrap(), "ok");

    let logs = fixture.logs().await;
    assert_eq!(
        logs.len(),
        1,
        "DNS override should have produced exactly one inbound connection"
    );
}

struct StaticResolver {
    target: SocketAddr,
    calls: Arc<AtomicUsize>,
}

impl Resolve for StaticResolver {
    fn resolve<'a>(&'a self, _host: &'a str, _port: u16) -> ResolveFuture<'a> {
        let target = self.target;
        let calls = self.calls.clone();
        Box::pin(async move {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(vec![target])
        })
    }
}

#[tokio::test]
async fn custom_dns_resolver_is_invoked_for_each_new_connection() {
    let fixture = H1Fixture::start().await;
    let calls = Arc::new(AtomicUsize::new(0));
    let resolver = Arc::new(StaticResolver {
        target: fixture.addr,
        calls: calls.clone(),
    });

    // Avoid pool reuse so the resolver is exercised on every request.
    let client = Client::builder()
        .prefer_http2(false)
        .pool_max_idle_per_host(0)
        .dns_resolver(resolver)
        .build()
        .unwrap();

    let host = "specter-custom-resolver.test";
    let url = format!("http://{}:{}/hello", host, fixture.addr.port());

    for _ in 0..3 {
        let response = client.get(url.as_str()).send().await.unwrap();
        assert_eq!(response.status().as_u16(), 200);
    }

    assert!(
        calls.load(Ordering::SeqCst) >= 3,
        "custom resolver should have been invoked at least once per request when pooling is disabled, got {}",
        calls.load(Ordering::SeqCst)
    );
}

#[tokio::test]
async fn pool_max_idle_per_host_zero_disables_h1_reuse() {
    let fixture = H1Fixture::start().await;
    let url = format!("http://127.0.0.1:{}/hello", fixture.addr.port());

    let client = Client::builder()
        .prefer_http2(false)
        .pool_max_idle_per_host(0)
        .build()
        .unwrap();

    for _ in 0..3 {
        let response = client.get(url.as_str()).send().await.unwrap();
        assert_eq!(response.status().as_u16(), 200);
    }

    let logs = fixture.logs().await;
    assert_eq!(
        logs.len(),
        3,
        "pool_max_idle_per_host(0) must force a fresh connection per request, got {}",
        logs.len()
    );
}

#[tokio::test]
async fn pool_idle_timeout_short_evicts_h1_connections() {
    let fixture = H1Fixture::start().await;
    let url = format!("http://127.0.0.1:{}/hello", fixture.addr.port());

    let client = Client::builder()
        .prefer_http2(false)
        .pool_idle_timeout(Duration::from_millis(50))
        .build()
        .unwrap();

    let r1 = client.get(url.as_str()).send().await.unwrap();
    assert_eq!(r1.status().as_u16(), 200);

    // Wait beyond the configured idle timeout.
    tokio::time::sleep(Duration::from_millis(150)).await;

    let r2 = client.get(url.as_str()).send().await.unwrap();
    assert_eq!(r2.status().as_u16(), 200);

    let logs = fixture.logs().await;
    assert_eq!(
        logs.len(),
        2,
        "expired pooled connection should not be reused after pool_idle_timeout",
    );
    assert_ne!(logs[0].connection_id, logs[1].connection_id);
}

#[tokio::test]
async fn pool_idle_timeout_long_allows_h1_reuse() {
    let fixture = H1Fixture::start().await;
    let url = format!("http://127.0.0.1:{}/hello", fixture.addr.port());

    let client = Client::builder()
        .prefer_http2(false)
        .pool_idle_timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    let r1 = client.get(url.as_str()).send().await.unwrap();
    assert_eq!(r1.status().as_u16(), 200);
    let r2 = client.get(url.as_str()).send().await.unwrap();
    assert_eq!(r2.status().as_u16(), 200);

    let logs = fixture.logs().await;
    assert_eq!(
        logs.len(),
        1,
        "pooled connection should be reused inside the configured idle window",
    );
}

#[tokio::test]
async fn h1_max_connections_per_origin_limits_active_parallelism() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let active = Arc::new(AtomicUsize::new(0));
    let max_active = Arc::new(AtomicUsize::new(0));
    let active_for_task = active.clone();
    let max_active_for_task = max_active.clone();

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let active = active_for_task.clone();
            let max_active = max_active_for_task.clone();
            tokio::spawn(async move {
                let mut buffer = Vec::new();
                let mut read_buf = [0u8; 1024];
                while !buffer.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = match stream.read(&mut read_buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    buffer.extend_from_slice(&read_buf[..n]);
                }

                let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                max_active.fetch_max(current, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(100)).await;
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
                let _ = stream.flush().await;
                active.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });

    let client = Client::builder()
        .prefer_http2(false)
        .pool_max_idle_per_host(0)
        .h1_max_connections_per_origin(1)
        .build()
        .unwrap();
    let url = format!("http://127.0.0.1:{}/slow", addr.port());

    let request = |client: Client, url: String| async move {
        let response = client.get(url.as_str()).send().await.unwrap();
        assert_eq!(response.status().as_u16(), 200);
        assert_eq!(response.text().unwrap(), "ok");
    };

    tokio::join!(
        request(client.clone(), url.clone()),
        request(client.clone(), url.clone()),
        request(client, url),
    );

    assert_eq!(
        max_active.load(Ordering::SeqCst),
        1,
        "h1_max_connections_per_origin(1) must queue active H1 requests instead of opening parallel sockets"
    );
}

#[test]
fn client_builder_exposes_h2_stream_capacity_knob() {
    let client = Client::builder()
        .h2_max_concurrent_streams_per_connection(17)
        .build()
        .unwrap();

    assert_eq!(
        client.h2_max_concurrent_streams_per_connection(),
        Some(17),
        "ClientBuilder must expose the local H2 stream cap used by the scheduler"
    );
}

#[test]
fn client_builder_exposes_h2_streaming_body_buffer_slots() {
    let client = Client::builder()
        .h2_streaming_body_buffer_slots(4)
        .build()
        .unwrap();

    assert_eq!(
        client.h2_streaming_body_buffer_slots(),
        4,
        "ClientBuilder must expose the H2 response-body queue slot cap"
    );
}

#[test]
fn client_builder_exposes_h3_streaming_body_buffer_slots() {
    let client = Client::builder()
        .h3_streaming_body_buffer_slots(3)
        .build()
        .unwrap();

    assert_eq!(
        client.h3_streaming_body_buffer_slots(),
        3,
        "ClientBuilder must expose the H3 response-body queue slot cap"
    );
    assert_eq!(
        client.h3_client().streaming_body_buffer_slots(),
        3,
        "ClientBuilder must propagate the H3 body slot cap into H3Client"
    );
}

#[tokio::test]
async fn client_builder_h3_max_idle_timeout_forces_reconnect() {
    let server = MockH3Server::new().await.unwrap();
    let connection_count = server.connection_count();
    let url = server.url();

    server.start(|conn| async move {
        for _ in 0..2 {
            let stream_id = loop {
                match conn.read_event().await {
                    Some(MockEvent::Headers { stream_id, .. }) => break stream_id,
                    Some(_) => continue,
                    None => return,
                }
            };
            conn.send_response_headers(stream_id, vec![(":status", "200")], false)
                .await;
            conn.send_response_data(stream_id, b"chunk", true).await;
        }
    });

    // Configure the unified Client::builder() H3 idle timeout to a small value.
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .h3_max_idle_timeout(100)
        .build()
        .unwrap();

    let h3 = client.h3_client().clone();

    let mut response1 = h3
        .send_streaming(&url, "GET", vec![], RequestBody::Empty)
        .await
        .unwrap();
    assert_eq!(response1.status(), 200);
    assert_eq!(
        response1
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        bytes::Bytes::from_static(b"chunk")
    );

    tokio::time::sleep(Duration::from_millis(250)).await;

    let mut response2 = h3
        .send_streaming(&url, "GET", vec![], RequestBody::Empty)
        .await
        .unwrap();
    assert_eq!(response2.status(), 200);
    assert_eq!(
        response2
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        bytes::Bytes::from_static(b"chunk")
    );

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        connection_count.load(Ordering::SeqCst),
        2,
        "Client::builder().h3_max_idle_timeout must propagate to the H3Client and force reconnect",
    );
}
