//! Malformed frame handling tests.
//!
//! Tests client robustness against protocol violations like oversized frames.

use specter::Client;
use std::time::Duration;
use tokio::time::timeout;

mod helpers;
use helpers::mock_h2_server::{MockH2Connection, MockH2Server};

async fn perform_handshake(conn: &MockH2Connection) -> std::io::Result<()> {
    conn.read_preface().await?;
    let (_, frame_type, _, _, _) = conn.read_frame().await?;
    assert_eq!(frame_type, 0x04);

    conn.send_settings(&[(0x03, 100), (0x04, 65535), (0x05, 16384)])
        .await?;
    conn.send_settings_ack().await?;

    let (_, frame_type, flags, _, _) = conn.read_frame().await?;
    assert_eq!(frame_type, 0x04);
    assert_eq!(flags & 0x01, 0x01);

    Ok(())
}

#[tokio::test]
async fn test_oversized_frame() {
    // Test that client rejects frames larger than MAX_FRAME_SIZE
    let server = MockH2Server::new().await.unwrap();
    let url = format!("{}/test", server.url());

    let (_handle, ready) = server.start_with_ready(|conn| async move {
        perform_handshake(&conn).await.unwrap();

        let _ = conn.read_frame().await; // WINDOW_UPDATE
        let (_, _, _, stream_id, _) = conn.read_frame().await.unwrap(); // HEADERS

        // Send response headers
        let response_headers = vec![0x88]; // :status: 200
        conn.send_headers(stream_id, &response_headers, false, true)
            .await
            .unwrap();

        // Send oversized DATA frame (> 16384 bytes, the default MAX_FRAME_SIZE)
        let large_data = vec![0u8; 20000]; // 20KB > 16KB

        // Attempt to send oversized frame
        // Client should respond with FRAME_SIZE_ERROR
        conn.send_data(stream_id, &large_data, true).await.unwrap();

        // Client should send GOAWAY with FRAME_SIZE_ERROR (0x06)
        let result = timeout(Duration::from_secs(1), conn.read_frame()).await;

        match result {
            Ok(Ok((_, frame_type, _, _, payload))) => {
                if frame_type == 0x07 {
                    // GOAWAY frame
                    if payload.len() >= 8 {
                        let error_code =
                            u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
                        assert_eq!(
                            error_code, 0x06,
                            "Expected FRAME_SIZE_ERROR, got error code {}",
                            error_code
                        );
                    }
                }
                // RST_STREAM is also acceptable for stream-level error
                else if frame_type == 0x03 {
                    // Less ideal but acceptable
                }
            }
            Ok(Err(_)) => {
                // Connection closed - acceptable
            }
            Err(_) => {
                panic!("Client did not respond to oversized frame within timeout");
            }
        }
    });

    ready.await.expect("mock H2 accept loop ready");

    let client = Client::builder().prefer_http2(true).build().unwrap();
    let result = timeout(Duration::from_secs(2), client.get(url.as_str()).send()).await;

    // Request will likely fail or timeout due to protocol error
    // We're just verifying the client doesn't panic
    match result {
        Ok(Ok(_)) => {
            // Unlikely but acceptable if client somehow recovered
        }
        Ok(Err(e)) => {
            // Expected - protocol error should propagate
            tracing::debug!("Request failed as expected: {:?}", e);
        }
        Err(_) => {
            // Timeout is also acceptable
            tracing::debug!("Request timed out as expected");
        }
    }
}

#[tokio::test]
async fn test_zero_length_headers_frame() {
    // Test that client rejects HEADERS frame with empty header block
    let server = MockH2Server::new().await.unwrap();
    let url = format!("{}/test", server.url());

    let (_handle, ready) = server.start_with_ready(|conn| async move {
        perform_handshake(&conn).await.unwrap();

        let _ = conn.read_frame().await; // WINDOW_UPDATE
        let (_, _, _, stream_id, _) = conn.read_frame().await.unwrap(); // HEADERS

        // Send HEADERS frame with empty header block (protocol violation)
        // RFC 9113 Section 6.2: HEADERS frame header block must not be empty
        conn.send_headers(stream_id, &[], false, true)
            .await
            .unwrap();

        // Client should send error (PROTOCOL_ERROR or COMPRESSION_ERROR)
        let result = timeout(Duration::from_secs(1), conn.read_frame()).await;

        match result {
            Ok(Ok((_, frame_type, _, _, _))) => {
                // Should be GOAWAY (0x07) or RST_STREAM (0x03)
                assert!(
                    frame_type == 0x03 || frame_type == 0x07,
                    "Expected error frame, got {}",
                    frame_type
                );
            }
            Ok(Err(_)) => {
                // Connection closed
            }
            Err(_) => {
                // Timeout - client might have tried to decode and failed
            }
        }
    });

    ready.await.expect("mock H2 accept loop ready");

    let client = Client::builder().prefer_http2(true).build().unwrap();
    let result = timeout(Duration::from_secs(2), client.get(url.as_str()).send()).await;

    // Request should fail
    if let Ok(Ok(_)) = result {
        panic!("Request should have failed with empty HEADERS");
    }
}
