//! PUSH_PROMISE handling tests.
//!
//! Verifies client correctly handles (or rejects) PUSH_PROMISE frames
//! based on SETTINGS_ENABLE_PUSH configuration.

use specter::Client;
use std::time::Duration;
use tokio::time::timeout;

mod helpers;
use helpers::mock_h2_server::{MockH2Connection, MockH2Server};

#[allow(dead_code)]
async fn perform_handshake(conn: &MockH2Connection) -> std::io::Result<()> {
    conn.read_preface().await?;
    let (_, frame_type, _, _, _) = conn.read_frame().await?;
    assert_eq!(frame_type, 0x04);

    conn.send_settings(&[(0x03, 100), (0x04, 65535)]).await?;
    conn.send_settings_ack().await?;

    let (_, frame_type, flags, _, _) = conn.read_frame().await?;
    assert_eq!(frame_type, 0x04);
    assert_eq!(flags & 0x01, 0x01);

    Ok(())
}

#[tokio::test]
async fn test_push_promise_when_disabled() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("trace")
        .try_init();

    // Test that client rejects PUSH_PROMISE when ENABLE_PUSH = 0
    let server = MockH2Server::new().await.unwrap();
    let url = format!("http://127.0.0.1:{}/test", server.port());

    let (_handle, ready) = server.start_with_ready(|conn| async move {
        tracing::info!("Server: Handshake start");
        conn.read_preface().await.unwrap();

        // Handshake Loop
        let stream_id = loop {
            let (len, frame_type, flags, sid, _) = conn.read_frame().await.unwrap();
            tracing::info!("Server: RX Type={} Flags={} Len={}", frame_type, flags, len);

            if frame_type == 0x01 {
                // HEADERS
                break sid;
            } else if frame_type == 0x04 && flags & 0x01 == 0 {
                // Settings (Client)
                conn.send_settings(&[(0x03, 100), (0x04, 65535)])
                    .await
                    .unwrap();
                conn.send_settings_ack().await.unwrap();
            }
        };

        tracing::info!("Server: Stream {} HEADERS received", stream_id);

        // Send valid response
        let response_headers = encode_response();
        conn.send_headers(stream_id, &response_headers, false, true)
            .await
            .unwrap();

        // Send PUSH_PROMISE (server tries to push /style.css)
        tracing::info!("Server: Sending PUSH_PROMISE");
        let push_headers = encode_push_headers();
        conn.send_push_promise(stream_id, 2, &push_headers)
            .await
            .unwrap();

        // Client should send RST_STREAM for stream 2 (promised stream)
        // It might also send SETTINGS ACK first.
        let start = std::time::Instant::now();
        loop {
            if start.elapsed() > Duration::from_secs(1) {
                panic!("Timeout waiting for RST_STREAM");
            }

            let result = timeout(Duration::from_millis(200), conn.read_frame()).await;
            match result {
                Ok(Ok((_, frame_type, _, rst_stream_id, payload))) => {
                    tracing::info!("Server: Received frame type {}", frame_type);

                    if frame_type == 0x03 {
                        // RST_STREAM
                        assert_eq!(
                            rst_stream_id, 2,
                            "RST_STREAM should be for promised stream 2"
                        );
                        if payload.len() >= 4 {
                            let error_code = u32::from_be_bytes([
                                payload[0], payload[1], payload[2], payload[3],
                            ]);
                            tracing::info!(
                                "Server: Received RST_STREAM error code: {}",
                                error_code
                            );
                            assert!(
                                error_code == 0x07 || error_code == 0x01,
                                "Expected REFUSED_STREAM or PROTOCOL_ERROR, got {}",
                                error_code
                            );
                        }
                        break; // Success
                    } else if frame_type == 0x07 {
                        // GOAWAY
                        tracing::info!("Server: Received GOAWAY");
                        break;
                    }
                    // Ignore other frames (like Settings Ack)
                }
                Ok(Err(e)) => {
                    tracing::info!("Server: Connection closed/error: {}", e);
                    break;
                }
                Err(_) => {
                    // Timeout on read
                    if start.elapsed() > Duration::from_secs(1) {
                        panic!("Timeout waiting for RST_STREAM");
                    }
                }
            }
        }

        // Complete the original response
        conn.send_data(stream_id, b"OK", true).await.unwrap();
    });

    ready.await.expect("mock H2 accept loop ready");

    let client = Client::builder()
        .prefer_http2(true)
        .http2_prior_knowledge(true)
        .build()
        .unwrap();
    let result = timeout(Duration::from_secs(2), client.get(url.as_str()).send()).await;

    assert!(result.is_ok(), "Request timed out");
    let response = result.unwrap();
    assert!(response.is_ok(), "Request failed: {:?}", response.err());
}

fn encode_response() -> Vec<u8> {
    vec![
        0x88, // :status: 200
    ]
}

fn encode_push_headers() -> Vec<u8> {
    // Minimal push promise headers
    // :method: GET
    // :scheme: https
    // :path: /style.css
    // :authority: 127.0.0.1

    vec![
        0x82, // :method: GET (static table index 2)
        0x87, // :scheme: https (static table index 7)
        0x44, 0x0a, // :path (static table index 4, value length 10)
        b'/', b's', b't', b'y', b'l', b'e', b'.', b'c', b's', b's', 0x01,
        0x09, // :authority (static table index 1, value length 9)
        b'1', b'2', b'7', b'.', b'0', b'.', b'0', b'.', b'1',
    ]
}
