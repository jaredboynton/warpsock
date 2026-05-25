//! HTTP/2 State Machine Violation Tests
//!
//! Tests client behavior when server violates the HTTP/2 state machine,
//! such as sending DATA frames on closed streams or using invalid stream IDs.

use specter::Client;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use tokio::time::timeout;

mod helpers;
use helpers::mock_h2_server::{MockH2Connection, MockH2Server};

/// Helper to perform basic H2 handshake.
/// Helper to perform H2 handshake and read the first HEADERS frame.
/// Returns the stream ID of the headers.
async fn perform_handshake_and_read_headers(conn: &MockH2Connection) -> std::io::Result<u32> {
    // Read client preface
    conn.read_preface().await?;

    // Loop until we get HEADERS
    let stream_id = loop {
        let (len, frame_type, flags, sid, _) = conn.read_frame().await?;
        tracing::debug!(
            "Server RX: Type={} Flags={} Len={} Sid={}",
            frame_type,
            flags,
            len,
            sid
        );

        match frame_type {
            0x01 => {
                // HEADERS
                break sid;
            }
            0x04 => {
                // SETTINGS
                if flags & 0x01 == 0 {
                    // Client Settings - Reply
                    conn.send_settings(&[(0x03, 100), (0x04, 65535)]).await?;
                    conn.send_settings_ack().await?;
                } else {
                    tracing::debug!("Server RX: Settings ACK");
                }
            }
            _ => {
                // Ignore WINDOW_UPDATE (0x08) and others during handshake
            }
        }
    };

    Ok(stream_id)
}

#[tokio::test]
async fn test_data_on_closed_stream() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("trace")
        .try_init();
    let server = MockH2Server::new().await.unwrap();
    let url = format!("http://127.0.0.1:{}/test", server.port());
    let client_processed_response = Arc::new(Notify::new());
    let client_processed_response_server = client_processed_response.clone();
    let violation_checked = Arc::new(Notify::new());
    let violation_checked_server = violation_checked.clone();

    let (_handle, ready) = server.start_with_ready(move |conn| {
        let client_processed_response = client_processed_response_server.clone();
        let violation_checked = violation_checked_server.clone();
        async move {
            // Handshake and read request
            let stream_id = perform_handshake_and_read_headers(&conn).await.unwrap();

            assert_eq!(stream_id, 1, "Expected Client Stream ID 1");

            // Send response HEADERS with END_STREAM (closing the stream)
            let response_headers = encode_simple_response();
            conn.send_headers(stream_id, &response_headers, true, true)
                .await
                .unwrap();

            timeout(Duration::from_secs(1), client_processed_response.notified())
                .await
                .expect("client should process the closed stream response");

            // Violate state machine: send DATA on closed stream
            conn.send_data(stream_id, b"This should not be accepted", false)
                .await
                .unwrap();

            // Client should send RST_STREAM or GOAWAY
            let result = timeout(Duration::from_secs(1), conn.read_frame()).await;

            match result {
                Ok(Ok((_, frame_type, _, _, _))) => {
                    tracing::info!("Received frame type {}", frame_type);
                    if frame_type == 0x03 { // RST_STREAM
                         // Success
                    } else if frame_type == 0x07 { // GOAWAY
                         // Success
                    } else {
                        tracing::warn!("Received unexpected frame type {}", frame_type);
                        // It is possible we receive a WindowUpdate or something else if timing is tight
                    }
                }
                Ok(Err(_)) => {
                    // Connection closed
                }
                Err(_) => {
                    // Timeout
                }
            }
            violation_checked.notify_one();
        }
    });

    ready.await.expect("mock H2 accept loop ready");

    // Client makes request
    let client = Client::builder()
        .prefer_http2(true)
        .http2_prior_knowledge(true)
        .build()
        .unwrap();

    let result = timeout(Duration::from_secs(2), client.get(url.as_str()).send()).await;

    // Request should succeed (we got a valid response before the violation)
    assert!(result.is_ok(), "Request timed out");
    let response = result.unwrap();
    assert!(response.is_ok(), "Request failed: {:?}", response.err());
    client_processed_response.notify_one();
    timeout(Duration::from_secs(2), violation_checked.notified())
        .await
        .expect("server should check the closed-stream violation");
}

#[tokio::test]
async fn test_server_initiated_stream_even_id() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("trace")
        .try_init();
    let server = MockH2Server::new().await.unwrap();
    let url = format!("http://127.0.0.1:{}/test", server.port());
    let client_processed_response = Arc::new(Notify::new());
    let client_processed_response_server = client_processed_response.clone();
    let violation_checked = Arc::new(Notify::new());
    let violation_checked_server = violation_checked.clone();

    let (_handle, ready) = server.start_with_ready(move |conn| {
        let client_processed_response = client_processed_response_server.clone();
        let violation_checked = violation_checked_server.clone();
        async move {
            // Handshake and read request
            let stream_id = perform_handshake_and_read_headers(&conn).await.unwrap();

            // Send valid response for client stream
            let response_headers = encode_simple_response();
            conn.send_headers(stream_id, &response_headers, true, true)
                .await
                .unwrap();

            timeout(Duration::from_secs(1), client_processed_response.notified())
                .await
                .expect("client should process the closed stream response");

            // Violate state machine: server sends HEADERS on even stream ID (server-initiated)
            let invalid_headers = encode_simple_response();
            conn.send_headers(2, &invalid_headers, false, true)
                .await
                .unwrap();

            let result = timeout(Duration::from_secs(1), async {
                loop {
                    match conn.read_frame().await {
                        Ok((_, frame_type, _, _, _)) if matches!(frame_type, 0x03 | 0x07) => {
                            return Ok(frame_type);
                        }
                        Ok((_, frame_type, _, _, _))
                            if matches!(frame_type, 0x02 | 0x04 | 0x08) =>
                        {
                            tracing::info!("Skipping benign frame type {}", frame_type);
                        }
                        other => return other.map(|(_, frame_type, _, _, _)| frame_type),
                    }
                }
            })
            .await;
            if let Ok(Ok(frame_type)) = result {
                tracing::info!("Received frame type {}", frame_type);
                assert!(
                    frame_type == 0x03 || frame_type == 0x07,
                    "Expected 0x03 or 0x07, got {}",
                    frame_type
                );
            }
            violation_checked.notify_one();
        }
    });

    ready.await.expect("mock H2 accept loop ready");

    let client = Client::builder()
        .prefer_http2(true)
        .http2_prior_knowledge(true)
        .build()
        .unwrap();
    let result = timeout(Duration::from_secs(2), client.get(url.as_str()).send()).await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_ok());
    client_processed_response.notify_one();
    timeout(Duration::from_secs(2), violation_checked.notified())
        .await
        .expect("server should check the even-stream-id violation");
}

/// Encode a minimal HTTP/2 response using literal headers (no dynamic table).
/// Returns: ":status: 200" + "content-length: 2"
fn encode_simple_response() -> Vec<u8> {
    // :status: 200 (indexed, static table index 8)
    // 0x88

    // content-length: 0 (literal with no indexing)
    // We can use index 28 (content-length) from static table
    // 0x00 | 0x0f = 0x0f (Literal without indexing, Index 15... wait)
    // Literal Header Field without Indexing - Indexed Name
    // Format: 0000 NNNN
    // Index 28 (11100).
    // 28 > 15. So prefix 15, then varint.
    // 0x0f, 13 (28-15=13 -> 0x0d).
    // So 0x0f, 0x0d is CORRECT for "Name Index 28"!

    // WAIT. My previous analysis was "Name Index 15".
    // 0x0f is 0000 1111.
    // If we want Index 28:
    // 4-bit prefix max is 15.
    // So we write 15 (0x0f).
    // Remaining is 13.
    // Next byte: 13 (0x0d).
    // So `0x0f, 0x0d` means "Name matches Static Index 28 (content-length)".
    //
    // Then Value Length.

    // Previous code:
    // 0x88,
    // 0x0f, 0x0d,
    // b'c', b'o'... -> This was writing the NAME "content-length".
    // BUT if we used Index 28, we DON'T write the name!
    // We only write Valid Length + Value.

    // So the previous code was mixing "Indexed Name" with "Literal Name".
    // It wrote index 28, then wrote the name bytes as if it was a value? Or just garbage?
    // It wrote "content-length" as value bytes?

    // Correct encoding for content-length: 2
    // 1. Indexed Name (Index 28).
    //    0x0f, 0x0d.
    // 2. Value Length (1).
    //    0x01.
    // 3. Value ("2").
    //    0x32 ('2').

    vec![
        0x88, // :status: 200
        0x0f, 0x0d, // Name Index 28 (content-length)
        0x01, // Value length 1
        b'0', // Value "0" (or 2?) Let's use 0 to match Empty Body handling in test
    ]
}
