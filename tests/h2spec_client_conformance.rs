//! h2spec client-conformance sweep (RFC 9113).
//!
//! h2spec (`summerwind/h2spec`) is a *server*-conformance tool: it drives a
//! client's frames at a server-under-test and asserts the server fails-closed.
//! Warpsock is an HTTP/2 *client*, so the client-relevant half of each h2spec
//! case is the mirror image: when a malicious/broken *server* emits the same
//! violation, the warpsock client must fail-closed (GOAWAY / RST_STREAM /
//! surfaced error) and never crash.
//!
//! Most h2spec sections are already mirrored by existing suites
//! (see docs/benchmarks/conformance/2026-07-07-h2/README.md for the full case
//! map). This file closes the two client-relevant gaps that had no dedicated
//! test:
//!   * RFC 9113 4.1 / 5.5  — client MUST ignore frames of unknown type.
//!   * RFC 9113 6.8        — client MUST handle a server GOAWAY gracefully.
//!
//! Deterministic: loopback mock server on 127.0.0.1:0, no fixed sleeps, all
//! synchronization via readiness channels + bounded timeouts.

use std::time::Duration;
use tokio::time::timeout;
use warpsock::Client;

mod helpers;
use helpers::mock_h2_server::{MockH2Connection, MockH2Server};

/// Drive the standard preface + SETTINGS exchange and return once the client
/// has acknowledged our SETTINGS. Mirrors the handshake helpers in the other
/// h2 suites but tolerates interleaved WINDOW_UPDATE frames.
async fn handshake_read_headers(conn: &MockH2Connection) -> std::io::Result<u32> {
    conn.read_preface().await?;
    let stream_id = loop {
        let (_, frame_type, flags, sid, _) = conn.read_frame().await?;
        match frame_type {
            0x01 => break sid, // HEADERS from client request
            0x04 => {
                if flags & 0x01 == 0 {
                    // client SETTINGS -> answer + ack
                    conn.send_settings(&[(0x03, 100), (0x04, 65535)]).await?;
                    conn.send_settings_ack().await?;
                }
            }
            _ => { /* ignore WINDOW_UPDATE / PRIORITY / etc. */ }
        }
    };
    Ok(stream_id)
}

/// Minimal `:status: 200` + `content-length: 0` HPACK block (static indices).
fn ok_response_headers() -> Vec<u8> {
    vec![
        0x88, // :status: 200 (static index 8)
        0x0f, 0x0d, // name index 28 (content-length)
        0x01, // value length 1
        b'0', // "0"
    ]
}

/// RFC 9113 4.1 / 5.5: "Implementations MUST ignore and discard frames of
/// unknown type." The client must not treat an unknown frame type interleaved
/// before the real response as an error; the request must still complete.
#[tokio::test]
async fn client_ignores_unknown_frame_type_rfc9113_5_5() {
    let server = MockH2Server::new().await.unwrap();
    let url = format!("http://127.0.0.1:{}/test", server.port());

    let (_handle, ready) = server.start_with_ready(|conn| async move {
        let stream_id = handshake_read_headers(&conn).await.unwrap();

        // Emit a frame with an unknown/experimental type (0x16) on the
        // connection stream. Per RFC 9113 the client MUST silently discard it.
        conn.send_frame(0x16, 0x00, 0, b"unknown-payload")
            .await
            .unwrap();

        // Then send a perfectly valid response.
        conn.send_headers(stream_id, &ok_response_headers(), true, true)
            .await
            .unwrap();
    });

    ready.await.expect("mock H2 accept loop ready");

    let client = Client::builder()
        .prefer_http2(true)
        .http2_prior_knowledge(true)
        .build()
        .unwrap();

    let result = timeout(Duration::from_secs(3), client.get(url.as_str()).send()).await;

    let resp = result
        .expect("request must not hang after an ignored unknown frame")
        .expect("client must ignore unknown frame type and complete the request");
    assert_eq!(
        resp.status(),
        200,
        "expected 200 after ignored unknown frame"
    );
}

/// RFC 9113 6.8: a client receiving GOAWAY must treat streams with an ID
/// greater than the advertised `Last-Stream-ID` as unprocessed. Here the
/// server sends GOAWAY (NO_ERROR, last-stream-id = 0) *before* responding to
/// stream 1, so stream 1 is unprocessed and the client MUST surface a clean
/// error rather than hang or panic.
#[tokio::test]
async fn client_handles_server_goaway_rfc9113_6_8() {
    let server = MockH2Server::new().await.unwrap();
    let url = format!("http://127.0.0.1:{}/test", server.port());

    let (_handle, ready) = server.start_with_ready(|conn| async move {
        let _stream_id = handshake_read_headers(&conn).await.unwrap();

        // GOAWAY with last_stream_id = 0 => our stream 1 was never processed.
        conn.send_goaway(0, 0).await.unwrap();
    });

    ready.await.expect("mock H2 accept loop ready");

    let client = Client::builder()
        .prefer_http2(true)
        .http2_prior_knowledge(true)
        .build()
        .unwrap();

    let result = timeout(Duration::from_secs(3), client.get(url.as_str()).send()).await;

    // Fail-closed: the request must resolve (not hang) and must not succeed,
    // because the server never delivered a response for stream 1.
    match result {
        Ok(Ok(_)) => panic!("request must not succeed after GOAWAY on an unprocessed stream"),
        Ok(Err(_)) => { /* clean protocol error surfaced — correct */ }
        Err(_) => panic!("client hung after server GOAWAY; must fail-closed promptly"),
    }
}
