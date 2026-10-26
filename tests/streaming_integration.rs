//! Low-level `H2Connection` streaming tests.
//!
//! The local tests stream from `MockH2Server` over TLS, so they're hermetic.
//! `test_real_streaming_cloudflare_trace` is the one live-network smoke test.
//!
//! Run with: cargo test --test streaming_integration

use bytes::Bytes;
use http::{Request, Uri};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use tokio::time::timeout;
use warpsock::fingerprint::http2::Http2Settings;
use warpsock::fingerprint::tls::TlsFingerprint;
use warpsock::transport::connector::BoringConnector;
use warpsock::transport::h2::hpack_impl::Encoder;
use warpsock::transport::h2::{H2Connection, PseudoHeaderOrder};

mod helpers;
use helpers::mock_h2_server::{MockH2Connection, MockH2Server};
use helpers::tls::generate_cert_bundle;

/// Starts a TLS HTTP/2 server that answers each request with `200` and a
/// `content-type`, waits for `release` if given, then sends `frames` as DATA
/// frames, ending the stream on the last one.
async fn serve(frames: Vec<Bytes>, release: Option<Arc<Notify>>) -> Uri {
    let (mut builder, _) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, protos| {
        boring::ssl::select_next_proto(b"\x02h2", protos).ok_or(boring::ssl::AlpnError::NOACK)
    });
    let server = MockH2Server::new().await.unwrap();
    let uri = format!("{}/stream", server.url_tls()).parse().unwrap();
    server.start_tls(builder.build(), move |conn: MockH2Connection| {
        let (frames, release) = (frames.clone(), release.clone());
        async move {
            conn.read_preface().await.unwrap();
            conn.send_settings(&[]).await.unwrap();
            conn.send_settings_ack().await.unwrap();
            let stream_id = loop {
                let (_, frame_type, _, stream_id, _) = conn.read_frame().await.unwrap();
                if frame_type == 0x01 {
                    break stream_id;
                }
            };
            let headers = Encoder::new().encode(&[
                (b":status".as_slice(), b"200".as_slice()),
                (
                    b"content-type".as_slice(),
                    b"application/octet-stream".as_slice(),
                ),
            ]);
            conn.send_headers(stream_id, &headers, false, true)
                .await
                .unwrap();
            if let Some(release) = release {
                release.notified().await;
            }
            for (i, frame) in frames.iter().enumerate() {
                conn.send_data(stream_id, frame, i + 1 == frames.len())
                    .await
                    .unwrap();
            }
        }
    });
    uri
}

/// Streams one GET to `uri` over `H2Connection` with the Chrome TLS
/// fingerprint. Fires `release` once `send_request_streaming` has returned the
/// response head, then drives the connection and collects the body chunks.
async fn stream_get(uri: &Uri, release: Option<&Notify>) -> (http::Response<Bytes>, Vec<Bytes>) {
    let stream = BoringConnector::with_fingerprint(TlsFingerprint::chrome_142())
        .danger_accept_invalid_certs(true)
        .connect(uri)
        .await
        .expect("TLS connection should succeed");
    assert!(stream.is_h2(), "server must negotiate HTTP/2");
    let mut conn =
        H2Connection::connect(stream, Http2Settings::default(), PseudoHeaderOrder::Chrome)
            .await
            .expect("HTTP/2 connection should succeed");
    let request = Request::get(uri).body(Bytes::new()).unwrap();
    let (response, mut rx) = timeout(Duration::from_secs(5), conn.send_request_streaming(request))
        .await
        .expect("response head must not wait for the body")
        .expect("streaming request should succeed");
    if let Some(release) = release {
        release.notify_one();
    }
    let driver =
        tokio::spawn(async move { while let Ok(true) = conn.read_streaming_frames().await {} });
    let chunks = timeout(Duration::from_secs(10), async {
        let mut chunks = Vec::new();
        while let Some(chunk) = rx.recv().await {
            chunks.push(chunk.expect("stream error"));
        }
        chunks
    })
    .await
    .expect("body should finish within 10 seconds");
    driver.abort();
    (response, chunks)
}

/// A 64 KiB body arrives as several DATA chunks, complete and in order.
#[tokio::test]
async fn streams_multi_frame_body_in_order() {
    let frames: Vec<Bytes> = (0..4u8)
        .map(|i| Bytes::from(vec![b'a' + i; 16_384]))
        .collect();
    let uri = serve(frames.clone(), None).await;

    let (response, chunks) = stream_get(&uri, None).await;

    assert_eq!(response.status(), 200);
    assert!(
        chunks.len() >= 2,
        "64 KiB should arrive in several chunks, got {}",
        chunks.len()
    );
    assert_eq!(chunks.concat(), frames.concat());
}

/// `send_request_streaming` returns the response head while the server is
/// still holding the body back.
#[tokio::test]
async fn returns_response_head_before_body() {
    let release = Arc::new(Notify::new());
    let uri = serve(
        vec![Bytes::from_static(b"late body")],
        Some(release.clone()),
    )
    .await;

    let (response, chunks) = stream_get(&uri, Some(&release)).await;

    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers()["content-type"],
        "application/octet-stream"
    );
    assert_eq!(chunks.concat(), b"late body");
}

/// Test streaming with Cloudflare's HTTP/2 SSE-style endpoint.
#[tokio::test]
async fn test_real_streaming_cloudflare_trace() {
    let fp = TlsFingerprint::chrome_142();
    let connector = BoringConnector::with_fingerprint(fp);
    let settings = Http2Settings::default();

    // Cloudflare's trace endpoint (returns small response, but validates H2 streaming works)
    let uri: Uri = "https://cloudflare.com/cdn-cgi/trace".parse().unwrap();

    let stream = connector
        .connect(&uri)
        .await
        .expect("TLS connection should succeed");

    if !stream.is_h2() {
        // Some Cloudflare endpoints may not negotiate H2, skip test
        tracing::info!("Cloudflare did not negotiate HTTP/2, skipping streaming test");
        return;
    }

    let mut h2_conn = H2Connection::connect(stream, settings, PseudoHeaderOrder::Chrome)
        .await
        .expect("HTTP/2 connection should succeed");

    // Build request without pseudo-headers
    let request = Request::builder()
        .method("GET")
        .uri(&uri)
        .header(
            "user-agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        )
        .header("accept", "*/*")
        .body(Bytes::new())
        .expect("Failed to build request");

    let (response, mut rx) = h2_conn
        .send_request_streaming(request)
        .await
        .expect("Streaming request should succeed");

    assert_eq!(response.status(), 200, "Should get 200 OK");

    // Collect response body via streaming
    let reader_handle = tokio::spawn(async move {
        let mut body = Vec::new();
        while let Some(result) = rx.recv().await {
            match result {
                Ok(chunk) => body.extend_from_slice(&chunk),
                Err(e) => panic!("Stream error: {}", e),
            }
        }
        body
    });

    // Drive connection
    let driver_handle = tokio::spawn(async move {
        loop {
            match h2_conn.read_streaming_frames().await {
                Ok(true) => continue,
                Ok(false) => break,
                Err(_) => break,
            }
        }
    });

    let body = timeout(Duration::from_secs(10), async {
        let _ = driver_handle.await;
        reader_handle.await.expect("Reader should complete")
    })
    .await
    .expect("Should complete within 10 seconds");

    let body_str = String::from_utf8_lossy(&body);
    assert!(
        body_str.contains("fl=") || body_str.contains("h="),
        "Cloudflare trace should contain connection info"
    );

    tracing::info!("Cloudflare streaming test passed: {} bytes", body.len());
}
