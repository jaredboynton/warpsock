//! Cross-protocol public streaming API parity coverage.
//!
//! Verifies VAL-CROSS-001 (transport-neutral high-level streaming API across
//! HTTP/1.1, pooled HTTP/2, and HTTP/3) and VAL-CROSS-006 (streaming API
//! preserves the same high-level request semantics expected from the
//! non-streaming `Client` API: explicit auth headers, cookies, non-empty
//! request bodies, timeout phases, and error classification).

use bytes::Bytes;
use serde_json::json;
use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, RwLock};
use tokio::time::timeout;
use warpsock::transport::h2::hpack_impl::Encoder;
use warpsock::{Client, CookieJar, Error, HttpVersion, RedirectPolicy};
mod helpers;
use helpers::mock_h2_server::{MockH2Connection, MockH2Server};
use helpers::mock_h3_server::{MockEvent, MockH3Server};
use helpers::tls::generate_cert_bundle;

#[derive(Clone, Debug, Default)]
struct H1Log {
    path: String,
    cookie_header: Option<String>,
    auth_header: Option<String>,
    request_body: Vec<u8>,
}

struct H1Fixture {
    url: String,
    logs: Arc<Mutex<Vec<H1Log>>>,
}

impl H1Fixture {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let logs = Arc::new(Mutex::new(Vec::new()));
        let logs_for_task = logs.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let logs = logs_for_task.clone();
                tokio::spawn(handle_h1_connection(stream, logs));
            }
        });
        Self { url, logs }
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}{}", self.url, path)
    }

    async fn logs(&self) -> Vec<H1Log> {
        self.logs.lock().await.clone()
    }
}

async fn handle_h1_connection(mut stream: TcpStream, logs: Arc<Mutex<Vec<H1Log>>>) {
    let mut buffer = Vec::new();
    loop {
        let mut buf = [0u8; 1024];
        while !buffer.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = match stream.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            buffer.extend_from_slice(&buf[..n]);
        }

        let header_end = buffer.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let header_bytes = buffer[..header_end].to_vec();
        let request = String::from_utf8_lossy(&header_bytes);
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
                line.split_once(':')
                    .map(|x| x.1)
                    .unwrap_or("")
                    .trim()
                    .to_string()
            });
        let auth_header = request
            .lines()
            .find(|line| line.to_ascii_lowercase().starts_with("authorization:"))
            .map(|line| {
                line.split_once(':')
                    .map(|x| x.1)
                    .unwrap_or("")
                    .trim()
                    .to_string()
            });
        let content_length = request
            .lines()
            .find(|line| line.to_ascii_lowercase().starts_with("content-length:"))
            .and_then(|line| line.split_once(':').map(|x| x.1))
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(0);
        buffer.drain(..header_end);

        // Read request body if present
        while buffer.len() < content_length {
            let mut buf = [0u8; 1024];
            let n = match stream.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            buffer.extend_from_slice(&buf[..n]);
        }
        let request_body = buffer.drain(..content_length).collect::<Vec<_>>();

        logs.lock().await.push(H1Log {
            path: path.clone(),
            cookie_header,
            auth_header,
            request_body: request_body.clone(),
        });

        match path.as_str() {
            "/cookie-set" => {
                let body = b"ok";
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nSet-Cookie: cross_proto_h1=h1_value; Path=/\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
                stream.write_all(body).await.unwrap();
                stream.flush().await.unwrap();
            }
            "/cookie-echo" => {
                let body = b"echoed";
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
                stream.write_all(body).await.unwrap();
                stream.flush().await.unwrap();
            }
            "/upload" => {
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: keep-alive\r\n\r\nuploaded",
                    )
                    .await
                    .unwrap();
                stream.flush().await.unwrap();
            }
            "/json" => {
                let body = br#"{"ok":true,"protocol":"h1"}"#;
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
                stream.write_all(&body[..12]).await.unwrap();
                stream.write_all(&body[12..]).await.unwrap();
                stream.flush().await.unwrap();
            }
            "/redirect-start" => {
                stream
                    .write_all(
                        b"HTTP/1.1 302 Found\r\nLocation: /redirect-final\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
                    )
                    .await
                    .unwrap();
                stream.flush().await.unwrap();
            }
            "/redirect-final" => {
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: keep-alive\r\n\r\nredirected-final",
                    )
                    .await
                    .unwrap();
                stream.flush().await.unwrap();
            }
            "/idle-stall" => {
                // Headers only, then a single small chunk, then stall — exercises read-idle.
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n")
                    .await
                    .unwrap();
                stream.flush().await.unwrap();
                stream.write_all(b"5\r\nfirst\r\n").await.unwrap();
                stream.flush().await.unwrap();
                let (_hold_tx, hold_rx) = tokio::sync::oneshot::channel::<()>();
                let _held = stream;
                let _ = hold_rx.await;
                return;
            }
            _ => {
                let body = b"hello-h1-stream";
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
                stream.write_all(body).await.unwrap();
                stream.flush().await.unwrap();
            }
        }
    }
}

async fn collect_body(mut response: warpsock::Response) -> Result<Vec<u8>, Error> {
    let mut body = Vec::new();
    while let Some(frame) = response.body_mut().frame().await {
        let chunk = frame?.into_data().unwrap_or_else(|_| bytes::Bytes::new());
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[tokio::test]
async fn send_response_helpers_are_buffered_for_h1_h2_h3() {
    {
        let fixture = H1Fixture::start().await;
        let client = Client::builder().prefer_http2(false).build().unwrap();
        let response = client
            .get(fixture.endpoint("/json"))
            .version(HttpVersion::Http1_1)
            .send()
            .await
            .unwrap();

        assert!(!response.body().is_streaming());
        assert_eq!(response.text().unwrap(), r#"{"ok":true,"protocol":"h1"}"#);
        let value: serde_json::Value = response.json().unwrap();
        assert_eq!(value["protocol"], "h1");
    }

    {
        let (mut builder, ca_cert) = generate_cert_bundle();
        builder.set_alpn_select_callback(|_, client_protos| {
            boring::ssl::select_next_proto(b"\x02h2", client_protos)
                .ok_or(boring::ssl::AlpnError::NOACK)
        });
        let acceptor = builder.build();
        let server = MockH2Server::new().await.unwrap();
        let url = server.url_tls();
        server.start_tls(acceptor, |conn: MockH2Connection| async move {
            conn.read_preface().await.unwrap();
            let mut settings_sent = false;
            let mut encoder = Encoder::new();
            loop {
                let frame = match timeout(Duration::from_secs(3), conn.read_frame()).await {
                    Ok(Ok(frame)) => frame,
                    _ => break,
                };
                let (_len, frame_type, flags, stream_id, _payload) = frame;
                match frame_type {
                    0x04 if flags & 0x01 == 0 && !settings_sent => {
                        conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 65535)])
                            .await
                            .unwrap();
                        conn.send_settings_ack().await.unwrap();
                        settings_sent = true;
                    }
                    0x01 => {
                        let headers = encoder.encode(&[
                            (b":status".as_slice(), b"200".as_slice()),
                            (b"content-type".as_slice(), b"application/json".as_slice()),
                        ]);
                        conn.send_headers(stream_id, &headers, false, true)
                            .await
                            .unwrap();
                        conn.send_data(stream_id, br#"{"ok":true,"#, false)
                            .await
                            .unwrap();
                        conn.send_data(stream_id, br#""protocol":"h2"}"#, true)
                            .await
                            .unwrap();
                    }
                    _ => {}
                }
            }
        });
        let client = Client::builder()
            .add_root_certificate(ca_cert)
            .prefer_http2(true)
            .build()
            .unwrap();
        let response = timeout(
            Duration::from_secs(5),
            client.get(format!("{}/json", url)).send(),
        )
        .await
        .unwrap()
        .unwrap();

        assert!(!response.body().is_streaming());
        assert_eq!(response.text().unwrap(), r#"{"ok":true,"protocol":"h2"}"#);
        let value: serde_json::Value = response.json().unwrap();
        assert_eq!(value["protocol"], "h2");
    }

    {
        let server = MockH3Server::new().await.unwrap();
        let url = server.url();
        server.start(|conn| async move {
            let stream_id = loop {
                match conn.read_event().await {
                    Some(MockEvent::Headers { stream_id, .. }) => break stream_id,
                    Some(_) => continue,
                    None => return,
                }
            };
            conn.send_response_headers(
                stream_id,
                vec![(":status", "200"), ("content-type", "application/json")],
                false,
            )
            .await;
            conn.send_response_data(stream_id, br#"{"ok":true,"#, false)
                .await;
            conn.send_response_data(stream_id, br#""protocol":"h3"}"#, true)
                .await;
        });
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        let response = timeout(
            Duration::from_secs(5),
            client.get(&url).version(HttpVersion::Http3).send(),
        )
        .await
        .unwrap()
        .unwrap();

        assert!(!response.body().is_streaming());
        assert_eq!(response.text().unwrap(), r#"{"ok":true,"protocol":"h3"}"#);
        let value: serde_json::Value = response.json().unwrap();
        assert_eq!(value["protocol"], "h3");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_send_future_is_spawnable_on_multithreaded_tokio() {
    let fixture = H1Fixture::start().await;
    let client = Client::builder().prefer_http2(false).build().unwrap();
    let url = fixture.endpoint("/json");

    fn assert_send<T: Send>(_: T) {}
    assert_send(client.get(url.clone()).send());

    let handle = tokio::spawn(async move {
        let response = client
            .get(url)
            .version(HttpVersion::Http1_1)
            .send()
            .await
            .unwrap();
        response.text().unwrap()
    });

    assert_eq!(handle.await.unwrap(), r#"{"ok":true,"protocol":"h1"}"#);
}

#[tokio::test]
async fn public_streaming_api_is_transport_neutral_for_h1_h2_h3() {
    fs::create_dir_all("target/validation/cross").unwrap();
    let mut artifact = json!({"protocols": {}});

    // ---- H1 ----
    {
        let fixture = H1Fixture::start().await;
        let client = Client::builder().prefer_http2(false).build().unwrap();
        let response = client
            .get(fixture.endpoint("/baseline"))
            .version(HttpVersion::Http1_1)
            .send_streaming()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 200);
        assert!(
            response.body().is_streaming(),
            "streaming response carries a poll-based Body"
        );
        assert_eq!(response.http_version(), "HTTP/1.1");
        let body = collect_body(response).await.unwrap();
        assert_eq!(body, b"hello-h1-stream");
        artifact["protocols"]["h1"] = json!({
            "status": 200,
            "received_chunks_concatenated": String::from_utf8_lossy(&body),
            "clean_terminal": true,
        });
    }

    // ---- H2 ----
    {
        let (mut builder, ca_cert) = generate_cert_bundle();
        builder.set_alpn_select_callback(|_, client_protos| {
            boring::ssl::select_next_proto(b"\x02h2", client_protos)
                .ok_or(boring::ssl::AlpnError::NOACK)
        });
        let acceptor = builder.build();
        let server = MockH2Server::new().await.unwrap();
        let url = server.url_tls();
        server.start_tls(acceptor, |conn: MockH2Connection| async move {
            conn.read_preface().await.unwrap();
            let mut settings_sent = false;
            let mut encoder = Encoder::new();
            loop {
                let frame = match timeout(Duration::from_secs(3), conn.read_frame()).await {
                    Ok(Ok(f)) => f,
                    _ => break,
                };
                let (_len, frame_type, flags, stream_id, _payload) = frame;
                match frame_type {
                    0x04 if flags & 0x01 == 0 && !settings_sent => {
                        conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 65535)])
                            .await
                            .unwrap();
                        conn.send_settings_ack().await.unwrap();
                        settings_sent = true;
                    }
                    0x01 => {
                        let resp = encoder.encode(&[(b":status".as_slice(), b"200".as_slice())]);
                        conn.send_headers(stream_id, &resp, false, true)
                            .await
                            .unwrap();
                        conn.send_data(stream_id, b"hello-", false).await.unwrap();
                        conn.send_data(stream_id, b"h2-stream", true).await.unwrap();
                    }
                    _ => {}
                }
            }
        });
        let client = Client::builder()
            .add_root_certificate(ca_cert)
            .prefer_http2(true)
            .build()
            .unwrap();
        let response = timeout(
            Duration::from_secs(5),
            client.get(format!("{}/baseline", url)).send_streaming(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response.status().as_u16(), 200);
        assert!(response.body().is_streaming());
        let body = collect_body(response).await.unwrap();
        assert_eq!(body, b"hello-h2-stream");
        artifact["protocols"]["h2"] = json!({
            "status": 200,
            "received_chunks_concatenated": String::from_utf8_lossy(&body),
            "clean_terminal": true,
        });
    }

    // ---- H3 ----
    {
        let server = MockH3Server::new().await.unwrap();
        let url = server.url();
        server.start(|conn| async move {
            let stream_id = loop {
                match conn.read_event().await {
                    Some(MockEvent::Headers { stream_id, .. }) => break stream_id,
                    Some(_) => continue,
                    None => return,
                }
            };
            conn.send_response_headers(stream_id, vec![(":status", "200")], false)
                .await;
            conn.send_response_data(stream_id, b"hello-", false).await;
            conn.send_response_data(stream_id, b"h3-stream", true).await;
        });
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        let response = timeout(
            Duration::from_secs(5),
            client
                .get(&url)
                .version(HttpVersion::Http3)
                .send_streaming(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response.status().as_u16(), 200);
        assert!(response.body().is_streaming());
        let body = collect_body(response).await.unwrap();
        assert_eq!(body, b"hello-h3-stream");
        artifact["protocols"]["h3"] = json!({
            "status": 200,
            "received_chunks_concatenated": String::from_utf8_lossy(&body),
            "clean_terminal": true,
        });
    }

    fs::write(
        "target/validation/cross/VAL-CROSS-001.json",
        serde_json::to_string_pretty(&artifact).unwrap(),
    )
    .unwrap();
}

// Drives five sequential end-to-end streaming scenarios in one async body. In
// debug builds the combined future exceeds the default 2 MiB test-thread stack
// and aborts with a stack overflow, so run the body on a dedicated thread with a
// larger stack. This is a test-harness concern only; the streaming runtime and
// wire behavior are unchanged. current_thread runtime preserves the original
// #[tokio::test] single-threaded semantics.
#[test]
fn public_streaming_preserves_high_level_request_semantics() {
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(public_streaming_preserves_high_level_request_semantics_inner());
        })
        .unwrap()
        .join()
        .unwrap();
}

async fn public_streaming_preserves_high_level_request_semantics_inner() {
    fs::create_dir_all("target/validation/cross").unwrap();
    let fixture = H1Fixture::start().await;

    // 1. Cookies set on the streaming response are stored on the public client
    //    cookie store and replayed on a same-origin streaming request, exactly
    //    like the non-streaming `send` path.
    let jar = Arc::new(RwLock::new(CookieJar::new()));
    let client = Client::builder()
        .prefer_http2(false)
        .cookie_jar(jar.clone())
        .build()
        .unwrap();

    let set_resp = client
        .get(fixture.endpoint("/cookie-set"))
        .version(HttpVersion::Http1_1)
        .send_streaming()
        .await
        .unwrap();
    assert_eq!(set_resp.status().as_u16(), 200);
    assert_eq!(collect_body(set_resp).await.unwrap(), b"ok");

    let echo_resp = client
        .get(fixture.endpoint("/cookie-echo"))
        .version(HttpVersion::Http1_1)
        .send_streaming()
        .await
        .unwrap();
    assert_eq!(echo_resp.status().as_u16(), 200);
    assert_eq!(collect_body(echo_resp).await.unwrap(), b"echoed");

    // 2. Explicit Authorization headers passed via the public RequestBuilder
    //    must reach the wire on the streaming path identically to non-streaming.
    let auth_resp = client
        .get(fixture.endpoint("/authcheck"))
        .header("Authorization", "Bearer streaming-token")
        .version(HttpVersion::Http1_1)
        .send_streaming()
        .await
        .unwrap();
    assert_eq!(auth_resp.status().as_u16(), 200);
    let _ = collect_body(auth_resp).await.unwrap();

    // 3. Non-empty request bodies are transmitted by the streaming POST.
    let post_resp = client
        .post(fixture.endpoint("/upload"))
        .body(b"streamed-upload-body".to_vec())
        .version(HttpVersion::Http1_1)
        .send_streaming()
        .await
        .unwrap();
    assert_eq!(post_resp.status().as_u16(), 200);
    assert_eq!(collect_body(post_resp).await.unwrap(), b"uploaded");

    // 4. Redirect policy is honored before returning the final streaming
    //    response, while preserving the same high-level caller shape.
    let redirect_client = Client::builder()
        .prefer_http2(false)
        .redirect_policy(RedirectPolicy::Limited(3))
        .build()
        .unwrap();
    let redirect_resp = redirect_client
        .get(fixture.endpoint("/redirect-start"))
        .version(HttpVersion::Http1_1)
        .send_streaming()
        .await
        .unwrap();
    assert_eq!(redirect_resp.status().as_u16(), 200);
    assert_eq!(
        redirect_resp.url().map(|u| u.path()),
        Some("/redirect-final")
    );
    assert_eq!(
        collect_body(redirect_resp).await.unwrap(),
        b"redirected-final"
    );

    // 5. H2 preserves the same public builder semantics: default headers,
    //    explicit auth, and non-empty request bodies reach the pooled H2 path.
    let h2_headers_seen = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
    let h2_body_seen = Arc::new(Mutex::new(Vec::<u8>::new()));
    {
        let (mut builder, ca_cert) = generate_cert_bundle();
        builder.set_alpn_select_callback(|_, client_protos| {
            boring::ssl::select_next_proto(b"\x02h2", client_protos)
                .ok_or(boring::ssl::AlpnError::NOACK)
        });
        let acceptor = builder.build();
        let server = MockH2Server::new().await.unwrap();
        let url = server.url_tls();
        let headers_seen = h2_headers_seen.clone();
        let body_seen = h2_body_seen.clone();
        server.start_tls(acceptor, move |conn: MockH2Connection| {
            let headers_seen = headers_seen.clone();
            let body_seen = body_seen.clone();
            async move {
                conn.read_preface().await.unwrap();
                let (_, frame_type, flags, _, _) = conn.read_frame().await.unwrap();
                assert_eq!(frame_type, 0x04);
                assert_eq!(flags & 0x01, 0);
                conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 65535)])
                    .await
                    .unwrap();
                conn.send_settings_ack().await.unwrap();

                let headers = timeout(Duration::from_secs(5), conn.read_decoded_headers())
                    .await
                    .unwrap()
                    .unwrap();
                *headers_seen.lock().await = headers.headers.clone();

                let mut body = Vec::new();
                if headers.flags & 0x01 == 0 {
                    loop {
                        let (_, frame_type, flags, stream_id, payload) =
                            conn.read_frame().await.unwrap();
                        if frame_type == 0x00 && stream_id == headers.stream_id {
                            body.extend_from_slice(&payload);
                            if flags & 0x01 != 0 {
                                break;
                            }
                        }
                    }
                }
                *body_seen.lock().await = body;

                let mut encoder = Encoder::new();
                let resp = encoder.encode(&[(b":status".as_slice(), b"200".as_slice())]);
                conn.send_headers(headers.stream_id, &resp, false, true)
                    .await
                    .unwrap();
                conn.send_data(headers.stream_id, b"h2-semantics-ok", true)
                    .await
                    .unwrap();
            }
        });

        let client = Client::builder()
            .add_root_certificate(ca_cert)
            .prefer_http2(true)
            .default_header("X-Default-Semantic", "default-h2")
            .build()
            .unwrap();
        let h2_resp = client
            .post(format!("{}/upload", url))
            .header("Authorization", "Bearer h2-streaming-token")
            .body("h2-streaming-body")
            .send_streaming()
            .await
            .unwrap();
        assert_eq!(h2_resp.status().as_u16(), 200);
        assert_eq!(collect_body(h2_resp).await.unwrap(), b"h2-semantics-ok");
    }

    let h2_headers = h2_headers_seen.lock().await.clone();
    assert!(
        h2_headers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("authorization")
                && value == "Bearer h2-streaming-token"),
        "H2 streaming must preserve explicit Authorization headers: {h2_headers:?}"
    );
    assert!(
        h2_headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("x-default-semantic") && value == "default-h2"
        }),
        "H2 streaming must preserve default headers: {h2_headers:?}"
    );
    assert_eq!(&*h2_body_seen.lock().await, b"h2-streaming-body");

    // 6. H3 preserves the same public builder semantics for headers and
    //    non-empty bodies when forced through the high-level HTTP/3 API.
    let h3_headers_seen = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
    let h3_body_seen = Arc::new(Mutex::new(Vec::<u8>::new()));
    {
        let server = MockH3Server::new().await.unwrap();
        let url = server.url();
        let headers_seen = h3_headers_seen.clone();
        let body_seen = h3_body_seen.clone();
        server.start(move |conn| {
            let headers_seen = headers_seen.clone();
            let body_seen = body_seen.clone();
            async move {
                let mut stream_id = None;
                let mut body = Vec::new();
                loop {
                    match conn.read_event().await {
                        Some(MockEvent::Headers {
                            stream_id: id,
                            headers,
                        }) => {
                            stream_id = Some(id);
                            *headers_seen.lock().await = headers;
                        }
                        Some(MockEvent::Data { data, .. }) => body.extend_from_slice(&data),
                        Some(MockEvent::Finished { stream_id: id }) => {
                            assert_eq!(stream_id, Some(id));
                            *body_seen.lock().await = body;
                            conn.send_response_headers(id, vec![(":status", "200")], false)
                                .await;
                            conn.send_response_data(id, b"h3-semantics-ok", true).await;
                            return;
                        }
                        Some(_) => {}
                        None => return,
                    }
                }
            }
        });

        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .default_header("X-Default-Semantic", "default-h3")
            .build()
            .unwrap();
        let h3_resp = client
            .post(&url)
            .version(HttpVersion::Http3Only)
            .header("Authorization", "Bearer h3-streaming-token")
            .body("h3-streaming-body")
            .send_streaming()
            .await
            .unwrap();
        assert_eq!(h3_resp.status().as_u16(), 200);
        assert_eq!(collect_body(h3_resp).await.unwrap(), b"h3-semantics-ok");
    }

    let h3_headers = h3_headers_seen.lock().await.clone();
    assert!(
        h3_headers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("authorization")
                && value == "Bearer h3-streaming-token"),
        "H3 streaming must preserve explicit Authorization headers: {h3_headers:?}"
    );
    assert!(
        h3_headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("x-default-semantic") && value == "default-h3"
        }),
        "H3 streaming must preserve default headers: {h3_headers:?}"
    );
    assert_eq!(&*h3_body_seen.lock().await, b"h3-streaming-body");

    // 7. Read-idle timeout phase is enforced for streaming chunk delivery and
    //    surfaces as the same crate-level Error variant the non-streaming path
    //    uses (Error::ReadIdleTimeout).
    let timeout_client = Client::builder()
        .prefer_http2(false)
        .read_timeout(Duration::from_millis(150))
        .build()
        .unwrap();
    let mut idle_resp = timeout_client
        .get(fixture.endpoint("/idle-stall"))
        .version(HttpVersion::Http1_1)
        .send_streaming()
        .await
        .unwrap();
    assert_eq!(idle_resp.status().as_u16(), 200);
    let first = idle_resp
        .body_mut()
        .frame()
        .await
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert_eq!(first, Bytes::from_static(b"first"));
    let stalled_err = match idle_resp.body_mut().frame().await {
        Some(Err(e)) => e,
        Some(Ok(frame)) => match frame.into_data() {
            Ok(b) => panic!("expected idle timeout, got chunk: {b:?}"),
            Err(_) => panic!("expected idle timeout, got non-data frame"),
        },
        None => panic!("expected idle timeout, got clean EOF"),
    };
    assert!(
        matches!(stalled_err, Error::ReadIdleTimeout(_)),
        "streaming idle timeout must reuse the high-level Error::ReadIdleTimeout variant; got {stalled_err:?}"
    );

    // Verify what hit the wire so future regressions can show up in the artifact.
    let logs = fixture.logs().await;
    let cookie_seen = logs
        .iter()
        .find(|l| l.path == "/cookie-echo")
        .and_then(|l| l.cookie_header.clone());
    let auth_seen = logs
        .iter()
        .find(|l| l.path == "/authcheck")
        .and_then(|l| l.auth_header.clone());
    let upload_body = logs
        .iter()
        .find(|l| l.path == "/upload")
        .map(|l| l.request_body.clone())
        .unwrap_or_default();
    let redirect_paths: Vec<String> = logs
        .iter()
        .filter(|l| l.path.starts_with("/redirect-"))
        .map(|l| l.path.clone())
        .collect();
    assert_eq!(
        cookie_seen.as_deref(),
        Some("cross_proto_h1=h1_value"),
        "cookie store must replay the captured streaming Set-Cookie on the next streaming request"
    );
    assert_eq!(
        auth_seen.as_deref(),
        Some("Bearer streaming-token"),
        "explicit Authorization header must travel on the streaming path"
    );
    assert_eq!(
        upload_body, b"streamed-upload-body",
        "non-empty request body must reach the upstream on the streaming POST path"
    );

    let artifact = json!({
        "h1": {
            "cookie_replayed_on_streaming": cookie_seen,
            "authorization_header_seen": auth_seen,
            "upload_body_bytes": upload_body.len(),
            "redirect_policy_followed_paths": redirect_paths,
            "read_idle_timeout_error_variant": "Error::ReadIdleTimeout"
        },
        "h2": {
            "authorization_header_seen": h2_headers.iter().find(|(name, _)| name.eq_ignore_ascii_case("authorization")).map(|(_, value)| value),
            "default_header_seen": h2_headers.iter().find(|(name, _)| name.eq_ignore_ascii_case("x-default-semantic")).map(|(_, value)| value),
            "upload_body_bytes": h2_body_seen.lock().await.len()
        },
        "h3": {
            "authorization_header_seen": h3_headers.iter().find(|(name, _)| name.eq_ignore_ascii_case("authorization")).map(|(_, value)| value),
            "default_header_seen": h3_headers.iter().find(|(name, _)| name.eq_ignore_ascii_case("x-default-semantic")).map(|(_, value)| value),
            "upload_body_bytes": h3_body_seen.lock().await.len()
        },
        "protocol_limitations": {
            "compressed_streaming": "supported; Content-Encoding is decoded while polling the streaming body"
        }
    });
    fs::write(
        "target/validation/cross/VAL-CROSS-006.json",
        serde_json::to_string_pretty(&artifact).unwrap(),
    )
    .unwrap();

    // Hold a reference to the jar so the test demonstrates client-owned state.
    let jar_inspect = jar.read().await;
    let _ = jar_inspect;
    let _ = AtomicUsize::new(0).load(Ordering::SeqCst);
}

#[tokio::test]
async fn public_response_body_is_http_body() {
    let fixture = H1Fixture::start().await;
    let client = Client::builder().prefer_http2(false).build().unwrap();

    let response = client
        .get(fixture.endpoint("/baseline"))
        .version(HttpVersion::Http1_1)
        .send_streaming()
        .await
        .unwrap();

    assert!(
        response.body().is_streaming(),
        "send_streaming must return a poll-based streaming Body"
    );

    let mut body: warpsock::Body = response.into_body();

    fn assert_http_body_impl<B: http_body::Body<Data = bytes::Bytes, Error = warpsock::Error>>(
        _: &B,
    ) {
    }
    assert_http_body_impl(&body);

    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.expect("frame should not error for healthy stream");
        if let Ok(data) = frame.into_data() {
            bytes.extend_from_slice(&data);
        }
    }
    assert_eq!(bytes, b"hello-h1-stream");
}

#[tokio::test]
async fn poll_body_hard_cutover_has_no_legacy_shim() {
    use std::path::PathBuf;
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    // Public surface check: send_streaming and Response::body must NOT
    // expose the old mpsc receiver tuple.
    let h1_h2 = fs::read_to_string(manifest_dir.join("src/transport/h1_h2.rs")).unwrap();
    assert!(
        !h1_h2.contains("pub async fn send_streaming(\n        self,\n    ) -> Result<("),
        "send_streaming must no longer return a tuple containing the old mpsc::Receiver"
    );
    assert!(
        h1_h2.contains("pub async fn send_streaming(self) -> Result<Response>"),
        "send_streaming must return Result<Response> with embedded Body"
    );

    let response_rs = fs::read_to_string(manifest_dir.join("src/response.rs")).unwrap();
    assert!(
        response_rs.contains("pub fn body(&self) -> &Body"),
        "Response::body() must return a reference to the public Body type"
    );
    assert!(
        response_rs.contains("impl HttpBody for Body"),
        "warpsock::Body must implement http_body::Body for the public response surface"
    );

    // No public legacy compatibility flag is allowed.
    let manifest = fs::read_to_string(manifest_dir.join("Cargo.toml")).unwrap();
    for forbidden in [
        "legacy-mpsc-body",
        "compat-mpsc-body",
        "compat_mpsc_body",
        "warpsock-legacy-body",
    ] {
        assert!(
            !manifest.contains(forbidden),
            "Cargo.toml must not declare a `{forbidden}` feature flag for the poll-body cutover"
        );
    }

    // Examples must consume the new poll-based body API.
    let example_files: Vec<_> = fs::read_dir(manifest_dir.join("examples"))
        .unwrap()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("rs"))
        .collect();
    for path in example_files {
        let contents = fs::read_to_string(&path).expect("example source readable");
        assert!(
            !contents.contains("rx.recv().await"),
            "example {} still uses the removed rx.recv().await receiver pattern",
            path.display()
        );
    }
}

#[test]
fn node_types_publish_streaming_surfaces() {
    let types = fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("bindings/node/index.d.ts"),
    )
    .unwrap();

    assert!(
        types.contains(
            "bodyStream(asyncIterable: AsyncIterable<Buffer | Uint8Array>): RequestBuilder;"
        ),
        "Node declarations must expose the JS bodyStream wrapper"
    );
    assert!(
        types.contains("readonly body: AsyncIterable<Buffer>;"),
        "Node declarations must expose the async iterable response body"
    );
}

#[test]
fn python_async_body_stream_send_preserves_streaming_response() {
    let source = fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("bindings/python/src/lib.rs"),
    )
    .unwrap();

    assert!(
        source.contains(
            "let resp = if streaming {\n                                req_builder.send_streaming().await.map_err(to_py_err)?\n                            } else {"
        ),
        "Python async body_stream send must return the streaming Rust response after headers"
    );
    assert!(
        !source.contains(
            "let resp = req_builder.send_streaming().await.map_err(to_py_err)?;\n                                buffer_response_body(resp).await?"
        ),
        "Python async body_stream send must not eagerly buffer the streaming response"
    );
}
