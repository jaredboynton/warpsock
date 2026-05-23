//! Cross-protocol public streaming API parity coverage.
//!
//! Verifies VAL-CROSS-001 (transport-neutral high-level streaming API across
//! HTTP/1.1, pooled HTTP/2, and HTTP/3) and VAL-CROSS-006 (streaming API
//! preserves the same high-level request semantics expected from the
//! non-streaming `Client` API: explicit auth headers, cookies, non-empty
//! request bodies, timeout phases, and error classification).

use bytes::Bytes;
use serde_json::json;
use specter::transport::h2::hpack_impl::Encoder;
use specter::{Client, CookieJar, Error, HttpVersion, RedirectPolicy};
use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, RwLock};
use tokio::time::timeout;
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
            .map(|line| line.splitn(2, ':').nth(1).unwrap_or("").trim().to_string());
        let auth_header = request
            .lines()
            .find(|line| line.to_ascii_lowercase().starts_with("authorization:"))
            .map(|line| line.splitn(2, ':').nth(1).unwrap_or("").trim().to_string());
        let content_length = request
            .lines()
            .find(|line| line.to_ascii_lowercase().starts_with("content-length:"))
            .and_then(|line| line.splitn(2, ':').nth(1))
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
                tokio::time::sleep(Duration::from_secs(60)).await;
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
                tokio::time::sleep(Duration::from_millis(20)).await;
                stream.write_all(body).await.unwrap();
                stream.flush().await.unwrap();
            }
        }
    }
}

async fn collect_body(
    mut rx: tokio::sync::mpsc::Receiver<Result<Bytes, Error>>,
) -> Result<Vec<u8>, Error> {
    let mut body = Vec::new();
    while let Some(chunk) = rx.recv().await {
        body.extend_from_slice(&chunk?);
    }
    Ok(body)
}

#[tokio::test]
async fn public_streaming_api_is_transport_neutral_for_h1_h2_h3() {
    fs::create_dir_all("target/validation/cross").unwrap();
    let mut artifact = json!({"protocols": {}});

    // ---- H1 ----
    {
        let fixture = H1Fixture::start().await;
        let client = Client::builder().prefer_http2(false).build().unwrap();
        let (response, rx) = client
            .get(fixture.endpoint("/baseline"))
            .version(HttpVersion::Http1_1)
            .send_streaming()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 200);
        assert!(
            response.body().is_empty(),
            "streaming response carries empty body"
        );
        assert_eq!(response.http_version(), "HTTP/1.1");
        let body = collect_body(rx).await.unwrap();
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
                    0x04 => {
                        if flags & 0x01 == 0 && !settings_sent {
                            conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 65535)])
                                .await
                                .unwrap();
                            conn.send_settings_ack().await.unwrap();
                            settings_sent = true;
                        }
                    }
                    0x01 => {
                        let resp = encoder.encode(&[(b":status".as_slice(), b"200".as_slice())]);
                        conn.send_headers(stream_id, &resp, false, true)
                            .await
                            .unwrap();
                        conn.send_data(stream_id, b"hello-", false).await.unwrap();
                        tokio::time::sleep(Duration::from_millis(20)).await;
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
        let (response, rx) = timeout(
            Duration::from_secs(5),
            client.get(format!("{}/baseline", url)).send_streaming(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response.status().as_u16(), 200);
        assert!(response.body().is_empty());
        let body = collect_body(rx).await.unwrap();
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
            tokio::time::sleep(Duration::from_millis(20)).await;
            conn.send_response_data(stream_id, b"h3-stream", true).await;
        });
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        let (response, rx) = timeout(
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
        assert!(response.body().is_empty());
        let body = collect_body(rx).await.unwrap();
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

#[tokio::test]
async fn public_streaming_preserves_high_level_request_semantics() {
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

    let (set_resp, set_rx) = client
        .get(fixture.endpoint("/cookie-set"))
        .version(HttpVersion::Http1_1)
        .send_streaming()
        .await
        .unwrap();
    assert_eq!(set_resp.status().as_u16(), 200);
    assert_eq!(collect_body(set_rx).await.unwrap(), b"ok");

    let (echo_resp, echo_rx) = client
        .get(fixture.endpoint("/cookie-echo"))
        .version(HttpVersion::Http1_1)
        .send_streaming()
        .await
        .unwrap();
    assert_eq!(echo_resp.status().as_u16(), 200);
    assert_eq!(collect_body(echo_rx).await.unwrap(), b"echoed");

    // 2. Explicit Authorization headers passed via the public RequestBuilder
    //    must reach the wire on the streaming path identically to non-streaming.
    let (auth_resp, auth_rx) = client
        .get(fixture.endpoint("/authcheck"))
        .header("Authorization", "Bearer streaming-token")
        .version(HttpVersion::Http1_1)
        .send_streaming()
        .await
        .unwrap();
    assert_eq!(auth_resp.status().as_u16(), 200);
    let _ = collect_body(auth_rx).await.unwrap();

    // 3. Non-empty request bodies are transmitted by the streaming POST.
    let (post_resp, post_rx) = client
        .post(fixture.endpoint("/upload"))
        .body(b"streamed-upload-body".to_vec())
        .version(HttpVersion::Http1_1)
        .send_streaming()
        .await
        .unwrap();
    assert_eq!(post_resp.status().as_u16(), 200);
    assert_eq!(collect_body(post_rx).await.unwrap(), b"uploaded");

    // 4. Redirect policy is honored before returning the final streaming
    //    response, while preserving the same high-level caller shape.
    let redirect_client = Client::builder()
        .prefer_http2(false)
        .redirect_policy(RedirectPolicy::Limited(3))
        .build()
        .unwrap();
    let (redirect_resp, redirect_rx) = redirect_client
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
        collect_body(redirect_rx).await.unwrap(),
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
        let (h2_resp, h2_rx) = client
            .post(format!("{}/upload", url))
            .header("Authorization", "Bearer h2-streaming-token")
            .body("h2-streaming-body")
            .send_streaming()
            .await
            .unwrap();
        assert_eq!(h2_resp.status().as_u16(), 200);
        assert_eq!(collect_body(h2_rx).await.unwrap(), b"h2-semantics-ok");
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
        let (h3_resp, h3_rx) = client
            .post(&url)
            .version(HttpVersion::Http3Only)
            .header("Authorization", "Bearer h3-streaming-token")
            .body("h3-streaming-body")
            .send_streaming()
            .await
            .unwrap();
        assert_eq!(h3_resp.status().as_u16(), 200);
        assert_eq!(collect_body(h3_rx).await.unwrap(), b"h3-semantics-ok");
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
    let (idle_resp, mut idle_rx) = timeout_client
        .get(fixture.endpoint("/idle-stall"))
        .version(HttpVersion::Http1_1)
        .send_streaming()
        .await
        .unwrap();
    assert_eq!(idle_resp.status().as_u16(), 200);
    let first = idle_rx.recv().await.unwrap().unwrap();
    assert_eq!(first, Bytes::from_static(b"first"));
    let stalled_err = match idle_rx.recv().await {
        Some(Err(e)) => e,
        Some(Ok(b)) => panic!("expected idle timeout, got chunk: {b:?}"),
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
            "compressed_streaming": "explicitly unsupported; compressed streaming returns Error::Decompression in transport tests"
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
