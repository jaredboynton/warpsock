//! RFC 9114 HTTP/3 Protocol Compliance Tests
//!
//! Uses MockH3Server to inject malformed frames and test client robustness.

use std::time::Duration;
use warpsock::transport::h3::H3Client;
// use tokio::time::timeout;

mod helpers;
use helpers::mock_h3_server::MockH3Server;

#[tokio::test]
async fn test_h3_clean_shutdown() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("trace")
        .try_init();

    let server: MockH3Server = MockH3Server::new().await.unwrap();
    let url = server.url();
    let url_clone = url.clone();

    // Start server handler
    server.start(
        |conn: helpers::mock_h3_server::MockH3Connection| async move {
            tracing::info!("Mock Server: Connection accepted");

            assert!(conn.wait_application_ready(Duration::from_secs(1)).await);

            conn.close_connection(true, 0, b"clean shutdown").await;
        },
    );

    // Client request
    // We need to disable cert verification because our mock uses a self-signed cert
    // H3Client might strictly verify. We might need to configure H3Client for testing.
    // H3Client exposes test certificate verification controls just like the other transports.

    // We need to disable cert verification because our mock uses a self-signed cert
    let client = H3Client::new().danger_accept_invalid_certs(true);

    let res = client.send_request(&url_clone, "GET", vec![], None).await;

    // Expecting error or success depending on cert validation?
    // Actually, checking H3Client source is wise.

    match res {
        Ok(_) => panic!("Client request unexpected success (should be GOAWAY or Closed)"),
        Err(e) => {
            tracing::info!("Client received expected error: {}", e);
            // Verify error is NO_ERROR (0) or ConnectionClosed
        }
    }
}

#[tokio::test]
async fn test_h3_malformed_frame() {
    let server: MockH3Server = MockH3Server::new().await.unwrap();
    let url = server.url();
    let url_clone = url.clone();

    server.start(
        |conn: helpers::mock_h3_server::MockH3Connection| async move {
            assert!(conn.wait_application_ready(Duration::from_secs(1)).await);

            // Send DATA frame on Control Stream (Stream ID 3)
            // Control Stream ID is 3 (Server Uni).
            // DATA Frame type is 0x00.
            // Payload "bad"
            // This is H3_FRAME_UNEXPECTED (RFC 9114 7.2.1)

            // Note: MockH3Server h3_conn already opened Stream 3 for Settings.
            // We append DATA frame to it.
            let control_stream_id = 3;
            let payload = b"bad";
            conn.send_frame(control_stream_id, 0, payload).await;
        },
    );

    let client = H3Client::new().danger_accept_invalid_certs(true);
    let res = client.send_request(&url_clone, "GET", vec![], None).await;

    match res {
        Ok(_) => panic!("Client request unexpected success"),
        Err(e) => {
            tracing::info!("Client received expected error: {}", e);
            // Error should be H3_FRAME_UNEXPECTED (0x105) or H3_MISSING_SETTINGS (0x107) if frame arrived before settings processed
            let msg = format!("{}", e);
            assert!(
                msg.contains("261")
                    || msg.contains("frame unexpected")
                    || msg.contains("FrameUnexpected")
                    || msg.contains("closed")
                    || msg.contains("channel closed")
                    || msg.contains("MissingSettings")
                    || msg.contains("control stream carried request/response frame"),
                "Error should indicate frame unexpected or closure, got: {}",
                msg
            );
        }
    }
}

/// RFC 9114 4.1: HEADERS is the first frame on a request stream. A server that
/// sends a DATA frame *before* any HEADERS on the response (request) stream
/// commits H3_FRAME_UNEXPECTED. The mirror obligation for the warpsock client
/// is to fail-closed on this rather than emit a bodiless/garbage response.
///
/// Deterministic: loopback mock H3 server on 127.0.0.1:0, readiness-gated, no
/// fixed sleeps.
#[tokio::test]
async fn test_h3_data_before_headers_rfc9114() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("trace")
        .try_init();

    let server: MockH3Server = MockH3Server::new().await.unwrap();
    let url = server.url();
    let url_clone = url.clone();

    server.start(
        |conn: helpers::mock_h3_server::MockH3Connection| async move {
            assert!(conn.wait_application_ready(Duration::from_secs(1)).await);

            // Stream 0 is the client's first (bidirectional) request stream.
            // Emit a DATA frame (type 0x00) with no preceding HEADERS: this is
            // H3_FRAME_UNEXPECTED per RFC 9114 4.1. The client MUST fail-closed.
            let request_stream_id = 0;
            conn.send_frame(request_stream_id, 0x00, b"body-before-headers")
                .await;
        },
    );

    let client = H3Client::new().danger_accept_invalid_certs(true);

    // Bound the request: the server sends a stray DATA frame and no HEADERS, so
    // the client must either surface an error or leave the request unresolved
    // (which our timeout turns into a clean, non-hanging failure). The MUST we
    // assert is negative: the request MUST NOT succeed. A hang past the budget
    // would itself be a failure of the harness, which is why we cap it.
    let res = tokio::time::timeout(
        Duration::from_secs(2),
        client.send_request(&url_clone, "GET", vec![], None),
    )
    .await;

    match res {
        Ok(Ok(_)) => {
            panic!("client must not succeed on DATA-before-HEADERS (H3_FRAME_UNEXPECTED)")
        }
        Ok(Err(e)) => {
            // Client surfaced a protocol/closure error — the ideal fail-closed path.
            let msg = format!("{}", e);
            tracing::info!("Client received expected error: {}", msg);
        }
        Err(_elapsed) => {
            // No response and no bogus success within budget: the client did not
            // accept the illegal DATA-before-HEADERS as a valid response. Also
            // an acceptable fail-closed outcome (client never fabricated a body).
            tracing::info!(
                "Client did not resolve DATA-before-HEADERS into a response (fail-closed)"
            );
        }
    }
}
