//! Error handling tests for the specter HTTP client.
//!
//! Tests client behavior under various failure conditions:
//! - Connection refused
//! - DNS resolution failure
//! - Read timeout (server accepts but never responds)
//! - Connection reset during body read
//! - TLS handshake failure

use specter::Client;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

mod helpers;

/// Connecting to a port with no listener should produce a connection error.
#[tokio::test]
async fn test_connection_refused() {
    // Bind a listener to get a port, then drop it immediately so nothing is listening.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let client = Client::builder().prefer_http2(false).build().unwrap();

    let url = format!("http://127.0.0.1:{}/test", port);
    let result = client.get(url.as_str()).send().await;

    assert!(result.is_err(), "Expected connection refused error");
    let err = result.unwrap_err();
    let err_msg = format!("{}", err);
    // The error should indicate a connection or IO failure.
    assert!(
        err_msg.contains("Connection") || err_msg.contains("IO") || err_msg.contains("refused"),
        "Expected connection-related error, got: {}",
        err_msg
    );
}

/// Connecting to an invalid/unresolvable hostname should produce a DNS or connection error.
#[tokio::test]
async fn test_dns_failure() {
    let client = Client::builder()
        .prefer_http2(false)
        .connect_timeout(Duration::from_secs(2))
        .build()
        .unwrap();

    let url = "http://this-host-does-not-exist-xyzzy-12345.invalid/test";
    let result = client.get(url).send().await;

    assert!(result.is_err(), "Expected DNS resolution error");
    let err = result.unwrap_err();
    let err_msg = format!("{}", err);
    // DNS failures typically surface as IO or Connection errors.
    assert!(
        err_msg.contains("IO")
            || err_msg.contains("Connection")
            || err_msg.contains("dns")
            || err_msg.contains("resolve")
            || err_msg.contains("No address")
            || err_msg.contains("not known")
            || err_msg.contains("nodename nor servname"),
        "Expected DNS-related error, got: {}",
        err_msg
    );
}

/// A server that accepts but never sends any data should trigger a TTFB timeout.
/// Uses a short real timeout (200ms) since the server never responds.
#[tokio::test]
async fn test_read_timeout_ttfb() {
    // Start a server that accepts connections but never responds.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            // Hold the connection open but never write anything.
            tokio::spawn(async move {
                let _held = stream;
                tokio::time::sleep(Duration::from_secs(3600)).await;
            });
        }
    });

    let client = Client::builder()
        .prefer_http2(false)
        .ttfb_timeout(Duration::from_millis(200))
        .total_timeout(Duration::from_millis(500))
        .build()
        .unwrap();

    let url = format!("http://127.0.0.1:{}/test", port);
    let result = client.get(url.as_str()).send().await;

    assert!(result.is_err(), "Expected timeout error");
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("timeout") || err_msg.contains("Timeout") || err_msg.contains("timed out"),
        "Expected timeout-related error, got: {}",
        err_msg
    );
}

/// A server that sends a partial HTTP response (headers only, no body) and then
/// closes the connection should produce an error when the client reads the body.
#[tokio::test]
async fn test_connection_reset_partial_response() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        // Read the request (just drain it).
        let mut buf = [0u8; 4096];
        let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;

        // Send partial HTTP response: headers claim 1000 bytes but we send only a few
        // then abruptly close.
        let partial =
            b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nConnection: close\r\n\r\nPartial";
        let _ = stream.write_all(partial).await;
        let _ = stream.flush().await;

        // Close the connection (simulates reset/truncation).
        drop(stream);
    });

    // Small delay so server is ready.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let client = Client::builder().prefer_http2(false).build().unwrap();

    let url = format!("http://127.0.0.1:{}/test", port);
    let result = client.get(url.as_str()).send().await;

    // The client might succeed in getting a response but with truncated body,
    // or it might fail during read. Either way, the body should not be 1000 bytes.
    match result {
        Ok(resp) => {
            // If we got a response, the body should be shorter than Content-Length claimed.
            let body_len = resp.buffered_bytes().map(|b| b.len()).unwrap_or(0);
            assert!(
                body_len < 1000,
                "Expected truncated body (got {} bytes)",
                body_len
            );
        }
        Err(e) => {
            // Connection reset error is also acceptable.
            let err_msg = format!("{}", e);
            assert!(
                err_msg.contains("IO")
                    || err_msg.contains("Connection")
                    || err_msg.contains("reset")
                    || err_msg.contains("closed")
                    || err_msg.contains("incomplete")
                    || err_msg.contains("unexpected eof")
                    || err_msg.contains("protocol"),
                "Expected connection/IO error, got: {}",
                err_msg
            );
        }
    }
}

/// Connecting with HTTPS to a plain TCP (non-TLS) server should fail with a TLS error.
#[tokio::test]
async fn test_tls_handshake_failure() {
    // Start a plain TCP server (no TLS).
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            // Send garbage that is not a valid TLS ServerHello.
            let _ = stream.write_all(b"This is not TLS").await;
            drop(stream);
        }
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Use a client that does NOT skip TLS verification for localhost.
    let client = Client::builder()
        .localhost_allows_invalid_certs(false)
        .connect_timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    let url = format!("https://127.0.0.1:{}/test", port);
    let result = client.get(url.as_str()).send().await;

    assert!(result.is_err(), "Expected TLS handshake error");
    let err_msg = format!("{}", result.unwrap_err());
    // TLS failures can appear as TLS, IO, or Connection errors.
    assert!(
        err_msg.contains("TLS")
            || err_msg.contains("tls")
            || err_msg.contains("SSL")
            || err_msg.contains("ssl")
            || err_msg.contains("handshake")
            || err_msg.contains("IO")
            || err_msg.contains("Connection"),
        "Expected TLS-related error, got: {}",
        err_msg
    );
}

/// When both connect and TTFB timeouts are set, the TTFB timeout fires for
/// a server that accepts connections but never sends headers.
/// This validates that granular timeouts compose correctly.
#[tokio::test]
async fn test_combined_timeouts() {
    // Server that accepts but never responds.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let _held = stream;
                tokio::time::sleep(Duration::from_secs(3600)).await;
            });
        }
    });

    // Set connect timeout generous (should succeed), TTFB tight (should fire).
    let client = Client::builder()
        .prefer_http2(false)
        .connect_timeout(Duration::from_secs(5))
        .ttfb_timeout(Duration::from_millis(200))
        .build()
        .unwrap();

    let url = format!("http://127.0.0.1:{}/test", port);
    let result = client.get(url.as_str()).send().await;

    assert!(result.is_err(), "Expected TTFB timeout error");
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("timeout") || err_msg.contains("Timeout") || err_msg.contains("TTFB"),
        "Expected timeout-related error, got: {}",
        err_msg
    );
}
