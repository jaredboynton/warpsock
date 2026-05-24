//! RFC 9110/9112 Compliance Tests for HTTP/1.1 implementation.
//!
//! These tests verify that the HTTP/1.1 client behaves correctly according to
//! the HTTP specifications.
//!
//! Note: Integration tests with the full Client use the existing mock server
//! infrastructure in tests/helpers/. Unit tests for RFC compliance are in
//! src/transport/h1.rs.

mod helpers;

use bytes::Bytes;
use helpers::mock_server::MockHttpServer;
use specter::Client;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// =============================================================================
// Basic HTTP/1.1 Tests with MockHttpServer
// =============================================================================

#[tokio::test]
async fn test_http11_basic_request() {
    let server = MockHttpServer::new().await.unwrap();
    let url = server.url();
    let _handle = server.start_with_request_limit(1);

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = Client::builder().prefer_http2(false).build().unwrap();
    let resp = client.get(url.as_str()).send().await.unwrap();

    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        resp.buffered_bytes().unwrap_or(&Bytes::new()).as_ref(),
        b"Hello"
    );
}

#[tokio::test]
async fn test_http11_connection_reuse() {
    let server = MockHttpServer::new().await.unwrap();
    let url = server.url();
    let _handle = server.start_with_request_limit(3);

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = Client::builder().prefer_http2(false).build().unwrap();

    // Multiple requests should reuse the connection
    for _ in 0..3 {
        let resp = client.get(url.as_str()).send().await.unwrap();
        assert_eq!(resp.status().as_u16(), 200);
    }
}

// =============================================================================
// Custom Response Tests
// =============================================================================

#[tokio::test]
async fn test_204_no_content_has_no_body() {
    // Per RFC 9112 Section 6.3: 204 responses MUST NOT contain a message body
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{}", port);

    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let _ = stream.read(&mut buf).await;
        // 204 with Content-Length (should be ignored per RFC)
        let response =
            b"HTTP/1.1 204 No Content\r\nContent-Length: 100\r\nConnection: close\r\n\r\n";
        let _ = stream.write_all(response).await;
        let _ = stream.flush().await;
        let _ = stream.shutdown().await; // Signal EOF to client
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = Client::builder().prefer_http2(false).build().unwrap();
    let resp = client.get(url.as_str()).send().await.unwrap();

    assert_eq!(resp.status().as_u16(), 204);
    // Body should be empty even though Content-Length says 100
    assert!(resp.body().is_empty());

    let _ = server_task.await;
}

#[tokio::test]
async fn test_304_not_modified_has_no_body() {
    // Per RFC 9112 Section 6.3: 304 responses MUST NOT contain a message body
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{}", port);

    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let _ = stream.read(&mut buf).await;
        let response = b"HTTP/1.1 304 Not Modified\r\nContent-Length: 50\r\nETag: \"abc123\"\r\nConnection: close\r\n\r\n";
        let _ = stream.write_all(response).await;
        let _ = stream.shutdown().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let client = Client::builder().prefer_http2(false).build().unwrap();
    let resp = client.get(url.as_str()).send().await.unwrap();

    assert_eq!(resp.status().as_u16(), 304);
    assert!(resp.body().is_empty());

    let _ = server_task.await;
}

#[tokio::test]
async fn test_chunked_transfer_encoding() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{}", port);

    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let _ = stream.read(&mut buf).await;
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let _ = stream.write_all(response).await;
        let _ = stream.shutdown().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let client = Client::builder().prefer_http2(false).build().unwrap();
    let resp = client.get(url.as_str()).send().await.unwrap();

    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        resp.buffered_bytes().unwrap_or(&Bytes::new()).as_ref(),
        b"hello"
    );

    let _ = server_task.await;
}

#[tokio::test]
async fn test_chunked_case_insensitive() {
    // Per RFC 9112: "chunked" comparison should be case-insensitive
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{}", port);

    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let _ = stream.read(&mut buf).await;
        // Use uppercase CHUNKED
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: CHUNKED\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let _ = stream.write_all(response).await;
        let _ = stream.shutdown().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let client = Client::builder().prefer_http2(false).build().unwrap();
    let resp = client.get(url.as_str()).send().await.unwrap();

    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        resp.buffered_bytes().unwrap_or(&Bytes::new()).as_ref(),
        b"hello"
    );

    let _ = server_task.await;
}

#[tokio::test]
async fn test_transfer_encoding_overrides_content_length() {
    // Per RFC 9112 Section 6.3: If Transfer-Encoding is present, Content-Length MUST be ignored
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{}", port);

    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let _ = stream.read(&mut buf).await;
        // Both TE and CL present - TE should win
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 999999\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let _ = stream.write_all(response).await;
        let _ = stream.shutdown().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let client = Client::builder().prefer_http2(false).build().unwrap();
    let resp = client.get(url.as_str()).send().await.unwrap();

    assert_eq!(resp.status().as_u16(), 200);
    // Should use chunked encoding, not Content-Length
    assert_eq!(
        resp.buffered_bytes().unwrap_or(&Bytes::new()).as_ref(),
        b"hello"
    );

    let _ = server_task.await;
}

#[tokio::test]
async fn test_chunked_with_trailers() {
    // Per RFC 9112 Section 7.1.2: Trailer section after last chunk
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{}", port);

    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let _ = stream.read(&mut buf).await;
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Checksum\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\nX-Checksum: abc123\r\n\r\n";
        let _ = stream.write_all(response).await;
        let _ = stream.shutdown().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let client = Client::builder().prefer_http2(false).build().unwrap();
    let resp = client.get(url.as_str()).send().await.unwrap();

    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        resp.buffered_bytes().unwrap_or(&Bytes::new()).as_ref(),
        b"hello"
    );

    let _ = server_task.await;
}

#[tokio::test]
async fn test_chunked_multiple_chunks() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{}", port);

    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let _ = stream.read(&mut buf).await;
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n1\r\n \r\n5\r\nworld\r\n0\r\n\r\n";
        let _ = stream.write_all(response).await;
        let _ = stream.shutdown().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let client = Client::builder().prefer_http2(false).build().unwrap();
    let resp = client.get(url.as_str()).send().await.unwrap();

    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        resp.buffered_bytes().unwrap_or(&Bytes::new()).as_ref(),
        b"hello world"
    );

    let _ = server_task.await;
}

#[tokio::test]
async fn test_content_length_exact() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{}", port);

    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let _ = stream.read(&mut buf).await;
        let response =
            b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nhello world";
        let _ = stream.write_all(response).await;
        let _ = stream.shutdown().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let client = Client::builder().prefer_http2(false).build().unwrap();
    let resp = client.get(url.as_str()).send().await.unwrap();

    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        resp.buffered_bytes().unwrap_or(&Bytes::new()).as_ref(),
        b"hello world"
    );

    let _ = server_task.await;
}

#[tokio::test]
async fn test_content_length_zero() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{}", port);

    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let _ = stream.read(&mut buf).await;
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let _ = stream.write_all(response).await;
        let _ = stream.shutdown().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let client = Client::builder().prefer_http2(false).build().unwrap();
    let resp = client.get(url.as_str()).send().await.unwrap();

    assert_eq!(resp.status().as_u16(), 200);
    assert!(resp.body().is_empty());

    let _ = server_task.await;
}

#[tokio::test]
async fn test_1xx_responses_skipped() {
    // Per RFC 9112: Client MUST be able to parse 1xx responses before final response
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{}", port);

    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let _ = stream.read(&mut buf).await;
        // Send 100 Continue followed by 200 OK
        let response = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";
        let _ = stream.write_all(response).await;
        let _ = stream.shutdown().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let client = Client::builder().prefer_http2(false).build().unwrap();
    let resp = client.get(url.as_str()).send().await.unwrap();

    // Should skip 100 Continue and return 200
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        resp.buffered_bytes().unwrap_or(&Bytes::new()).as_ref(),
        b"hello"
    );

    let _ = server_task.await;
}

#[tokio::test]
async fn test_close_delimited_body() {
    // Per RFC 9112 Section 6.3: If no Content-Length or Transfer-Encoding,
    // body is delimited by connection close
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{}", port);

    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let _ = stream.read(&mut buf).await;
        // No Content-Length, no Transfer-Encoding - body ends when connection closes
        let response = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nThis body is close-delimited";
        let _ = stream.write_all(response).await;
        let _ = stream.shutdown().await; // Signal EOF - this is what ends the body
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let client = Client::builder().prefer_http2(false).build().unwrap();
    let resp = client.get(url.as_str()).send().await.unwrap();

    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        resp.buffered_bytes().unwrap_or(&Bytes::new()).as_ref(),
        b"This body is close-delimited"
    );

    let _ = server_task.await;
}
