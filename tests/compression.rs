//! Content-Encoding / Compression Tests
//!
//! Tests that the specter client correctly handles compressed responses:
//! - gzip Content-Encoding
//! - deflate Content-Encoding
//! - brotli Content-Encoding
//! - zstd Content-Encoding
//! - Identity (no compression) baseline

use specter::Client;
use std::io::Write;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

mod helpers;

const TEST_BODY: &str =
    "Hello, compressed world! This is a test payload for verifying decompression.";

/// Start a mock HTTP/1.1 server that returns a response with the given
/// Content-Encoding header and pre-compressed body bytes.
async fn start_encoding_server(
    content_encoding: &'static str,
    compressed_body: Vec<u8>,
) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{}/test", port);

    let handle = tokio::spawn(async move {
        // Accept one connection.
        let (mut stream, _) = listener.accept().await.unwrap();

        // Read the request (drain it).
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf).await;

        // Build the response.
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Encoding: {}\r\n\
             Content-Length: {}\r\n\
             Content-Type: text/plain\r\n\
             Connection: close\r\n\
             \r\n",
            content_encoding,
            compressed_body.len()
        );

        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.write_all(&compressed_body).await;
        let _ = stream.flush().await;
    });

    (url, handle)
}

/// Compress bytes with gzip.
fn gzip_compress(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

/// Compress bytes with deflate (zlib wrapper, which is what HTTP "deflate" means per RFC 7230).
fn deflate_compress(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

/// Compress bytes with brotli.
fn brotli_compress(data: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    {
        let mut writer = brotli::CompressorWriter::new(&mut output, 4096, 6, 22);
        writer.write_all(data).unwrap();
        // Flush on drop.
    }
    output
}

/// Compress bytes with zstd.
fn zstd_compress(data: &[u8]) -> Vec<u8> {
    zstd::encode_all(data, 3).unwrap()
}

/// Test transparent gzip decompression.
#[tokio::test]
async fn test_gzip_decompression() {
    let compressed = gzip_compress(TEST_BODY.as_bytes());
    let (url, _handle) = start_encoding_server("gzip", compressed).await;

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let client = Client::builder().prefer_http2(false).build().unwrap();

    let resp = client
        .get(url.as_str())
        .send()
        .await
        .expect("Request failed");

    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        resp.content_encoding(),
        Some("gzip"),
        "Content-Encoding header should be gzip"
    );

    // The decoded body should match the original text.
    let text = resp.text().expect("Failed to decode response body");
    assert_eq!(text, TEST_BODY, "Decompressed body does not match original");
}

/// Test transparent deflate decompression.
#[tokio::test]
async fn test_deflate_decompression() {
    let compressed = deflate_compress(TEST_BODY.as_bytes());
    let (url, _handle) = start_encoding_server("deflate", compressed).await;

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let client = Client::builder().prefer_http2(false).build().unwrap();

    let resp = client
        .get(url.as_str())
        .send()
        .await
        .expect("Request failed");

    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(resp.content_encoding(), Some("deflate"));

    let text = resp.text().expect("Failed to decode response body");
    assert_eq!(
        text, TEST_BODY,
        "Decompressed deflate body does not match original"
    );
}

/// Test transparent brotli decompression.
#[tokio::test]
async fn test_brotli_decompression() {
    let compressed = brotli_compress(TEST_BODY.as_bytes());
    let (url, _handle) = start_encoding_server("br", compressed).await;

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let client = Client::builder().prefer_http2(false).build().unwrap();

    let resp = client
        .get(url.as_str())
        .send()
        .await
        .expect("Request failed");

    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(resp.content_encoding(), Some("br"));

    let text = resp.text().expect("Failed to decode response body");
    assert_eq!(
        text, TEST_BODY,
        "Decompressed brotli body does not match original"
    );
}

/// Test transparent zstd decompression.
#[tokio::test]
async fn test_zstd_decompression() {
    let compressed = zstd_compress(TEST_BODY.as_bytes());
    let (url, _handle) = start_encoding_server("zstd", compressed).await;

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let client = Client::builder().prefer_http2(false).build().unwrap();

    let resp = client
        .get(url.as_str())
        .send()
        .await
        .expect("Request failed");

    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(resp.content_encoding(), Some("zstd"));

    let text = resp.text().expect("Failed to decode response body");
    assert_eq!(
        text, TEST_BODY,
        "Decompressed zstd body does not match original"
    );
}

/// Test that identity (no compression) works correctly and returns the raw body.
#[tokio::test]
async fn test_identity_no_compression() {
    let plain_body = TEST_BODY.as_bytes().to_vec();
    let (url, _handle) = start_encoding_server("identity", plain_body).await;

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let client = Client::builder().prefer_http2(false).build().unwrap();

    let resp = client
        .get(url.as_str())
        .send()
        .await
        .expect("Request failed");

    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(resp.content_encoding(), Some("identity"));

    let text = resp.text().expect("Failed to decode response body");
    assert_eq!(text, TEST_BODY, "Identity body does not match original");
}

/// Test that raw bytes can be accessed without decompression via bytes_raw().
#[tokio::test]
async fn test_raw_bytes_vs_decoded() {
    let compressed = gzip_compress(TEST_BODY.as_bytes());
    let compressed_len = compressed.len();
    let (url, _handle) = start_encoding_server("gzip", compressed).await;

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let client = Client::builder().prefer_http2(false).build().unwrap();

    let resp = client
        .get(url.as_str())
        .send()
        .await
        .expect("Request failed");

    // Raw bytes should be the compressed form.
    let raw = resp.bytes_raw().expect("Buffered raw bytes");
    assert_eq!(
        raw.len(),
        compressed_len,
        "Raw bytes length should match compressed size"
    );

    // Decoded bytes should be the original text.
    let decoded = resp.bytes().expect("Decode failed");
    assert_eq!(decoded.as_ref(), TEST_BODY.as_bytes());

    // They should differ (compressed != uncompressed).
    assert_ne!(
        raw.as_ref(),
        decoded.as_ref(),
        "Raw and decoded bytes should differ for compressed responses"
    );
}
