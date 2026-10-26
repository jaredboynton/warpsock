//! Live-network smoke test: low-level `H2Connection` streaming against
//! Cloudflare. `tests/live_*.rs` binaries stay out of the CI gate (nextest `ci`
//! profile) and run in `.github/workflows/live-network.yml`.

use bytes::Bytes;
use http::{Request, Uri};
use std::time::Duration;
use tokio::time::timeout;
use warpsock::fingerprint::http2::Http2Settings;
use warpsock::fingerprint::tls::TlsFingerprint;
use warpsock::transport::connector::BoringConnector;
use warpsock::transport::h2::{H2Connection, PseudoHeaderOrder};

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
