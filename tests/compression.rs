//! Content-Encoding / Compression Tests
//!
//! Tests that the warpsock client correctly handles compressed responses:
//! - gzip Content-Encoding
//! - deflate Content-Encoding
//! - brotli Content-Encoding
//! - zstd Content-Encoding
//! - Identity (no compression) baseline

use std::io::Write;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use warpsock::transport::h2::{flags, hpack_impl::Encoder};
use warpsock::Client;

mod helpers;
use helpers::mock_h2_server::MockH2Server;
use helpers::tls::generate_cert_bundle;

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

fn raw_deflate_compress(data: &[u8]) -> Vec<u8> {
    let mut encoder =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
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

#[tokio::test]
async fn h2_padded_zstd_response_decodes_exact_body() {
    let body = TEST_BODY.repeat(2048).into_bytes();
    let compressed = zstd_compress(&body);
    let split = compressed.len() / 2;
    let first_chunk = compressed[..split].to_vec();
    let second_chunk = compressed[split..].to_vec();

    let server = MockH2Server::new().await.unwrap();
    let url = format!("http://127.0.0.1:{}/zstd", server.port());

    let _handle = server.start(move |conn| {
        let first_chunk = first_chunk.clone();
        let second_chunk = second_chunk.clone();
        async move {
            conn.read_preface().await.unwrap();
            let stream_id = loop {
                let (_, frame_type, frame_flags, stream_id, _) = conn.read_frame().await.unwrap();
                match frame_type {
                    0x01 => break stream_id,
                    0x04 if frame_flags & flags::ACK == 0 => {
                        conn.send_settings(&[]).await.unwrap();
                        conn.send_settings_ack().await.unwrap();
                    }
                    _ => {}
                }
            };

            let mut encoder = Encoder::new();
            let headers = encoder.encode(&[
                (b":status".as_slice(), b"200".as_slice()),
                (b"content-encoding".as_slice(), b"zstd".as_slice()),
                (b"content-type".as_slice(), b"text/plain".as_slice()),
            ]);
            conn.send_headers(stream_id, &headers, false, true)
                .await
                .unwrap();

            let mut first_payload = Vec::with_capacity(first_chunk.len() + 4);
            first_payload.push(3);
            first_payload.extend_from_slice(&first_chunk);
            first_payload.extend_from_slice(&[0, 0, 0]);
            conn.send_frame(0x00, flags::PADDED, stream_id, &first_payload)
                .await
                .unwrap();

            let mut second_payload = Vec::with_capacity(second_chunk.len() + 6);
            second_payload.push(5);
            second_payload.extend_from_slice(&second_chunk);
            second_payload.extend_from_slice(&[0, 0, 0, 0, 0]);
            conn.send_frame(
                0x00,
                flags::PADDED | flags::END_STREAM,
                stream_id,
                &second_payload,
            )
            .await
            .unwrap();
        }
    });

    let client = Client::builder()
        .prefer_http2(true)
        .http2_prior_knowledge(true)
        .build()
        .unwrap();
    let resp = client.get(url.as_str()).send().await.unwrap();

    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(resp.content_encoding(), Some("zstd"));
    assert_eq!(
        resp.bytes_raw().expect("raw body").as_ref(),
        compressed.as_slice()
    );
    assert_eq!(
        resp.bytes().expect("decoded body").as_ref(),
        body.as_slice()
    );
}

#[tokio::test]
async fn h2_streaming_gzip_response_decodes_split_data_frames() {
    let body = TEST_BODY.repeat(64).into_bytes();
    let compressed = gzip_compress(&body);
    let split = compressed.len() / 2;
    let first_chunk = compressed[..split].to_vec();
    let second_chunk = compressed[split..].to_vec();

    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();
    let server = MockH2Server::new().await.unwrap();
    let url = format!("{}/gzip-stream", server.url_tls());

    let _handle = server.start_tls(acceptor, move |conn| {
        let first_chunk = first_chunk.clone();
        let second_chunk = second_chunk.clone();
        async move {
            conn.read_preface().await.unwrap();
            let stream_id = loop {
                let (_, frame_type, frame_flags, stream_id, _) = conn.read_frame().await.unwrap();
                match frame_type {
                    0x01 => break stream_id,
                    0x04 if frame_flags & flags::ACK == 0 => {
                        conn.send_settings(&[]).await.unwrap();
                        conn.send_settings_ack().await.unwrap();
                    }
                    _ => {}
                }
            };

            let mut encoder = Encoder::new();
            let headers = encoder.encode(&[
                (b":status".as_slice(), b"200".as_slice()),
                (b"content-encoding".as_slice(), b"gzip".as_slice()),
                (b"content-type".as_slice(), b"text/plain".as_slice()),
            ]);
            conn.send_headers(stream_id, &headers, false, true)
                .await
                .unwrap();
            conn.send_data(stream_id, &first_chunk, false)
                .await
                .unwrap();
            conn.send_data(stream_id, &second_chunk, true)
                .await
                .unwrap();
        }
    });

    let client = Client::builder()
        .add_root_certificate(ca_cert)
        .prefer_http2(true)
        .build()
        .unwrap();
    let mut resp = client.get(url.as_str()).send_streaming().await.unwrap();

    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(resp.content_encoding(), Some("gzip"));
    assert_eq!(
        resp.body_mut().collect_to_bytes().await.unwrap().as_ref(),
        body.as_slice()
    );
}

#[tokio::test]
async fn invalid_streaming_gzip_errors_while_polling_body() {
    let (url, _handle) = start_encoding_server("gzip", b"not a gzip stream".to_vec()).await;
    let client = Client::builder().prefer_http2(false).build().unwrap();

    let mut resp = client
        .get(url.as_str())
        .send_streaming()
        .await
        .expect("headers should still arrive for malformed gzip");

    let err = resp
        .body_mut()
        .collect_to_bytes()
        .await
        .expect_err("malformed gzip should fail while polling body");
    assert!(
        matches!(err, warpsock::Error::Decompression(_)),
        "expected decompression error, got {err:?}"
    );
}

#[tokio::test]
async fn streaming_chained_content_encoding_decodes_in_reverse_order() {
    let gzip = gzip_compress(TEST_BODY.as_bytes());
    let gzip_then_brotli = brotli_compress(&gzip);
    let (url, _handle) = start_encoding_server("gzip, br", gzip_then_brotli).await;
    let client = Client::builder().prefer_http2(false).build().unwrap();

    let mut resp = client.get(url.as_str()).send_streaming().await.unwrap();

    assert_eq!(resp.content_encoding(), Some("gzip, br"));
    assert_eq!(
        resp.body_mut().collect_to_bytes().await.unwrap().as_ref(),
        TEST_BODY.as_bytes()
    );
}

#[tokio::test]
async fn streaming_deflate_accepts_raw_deflate_fallback() {
    let raw_deflate = raw_deflate_compress(TEST_BODY.as_bytes());
    let (url, _handle) = start_encoding_server("deflate", raw_deflate).await;
    let client = Client::builder().prefer_http2(false).build().unwrap();

    let mut resp = client.get(url.as_str()).send_streaming().await.unwrap();

    assert_eq!(
        resp.body_mut().collect_to_bytes().await.unwrap().as_ref(),
        TEST_BODY.as_bytes()
    );
}

#[tokio::test]
async fn partial_content_streaming_gzip_is_not_decoded() {
    let compressed = gzip_compress(TEST_BODY.as_bytes());
    let compressed_for_server = compressed.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{}/partial", port);

    let _handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf).await;
        let response = format!(
            "HTTP/1.1 206 Partial Content\r\n\
             Content-Encoding: gzip\r\n\
             Content-Range: bytes 0-{}/{}\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n",
            compressed_for_server.len() - 1,
            compressed_for_server.len(),
            compressed_for_server.len()
        );
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.write_all(&compressed_for_server).await;
        let _ = stream.flush().await;
    });

    let client = Client::builder().prefer_http2(false).build().unwrap();
    let mut resp = client.get(url.as_str()).send_streaming().await.unwrap();

    assert_eq!(resp.status().as_u16(), 206);
    assert_eq!(
        resp.body_mut().collect_to_bytes().await.unwrap().as_ref(),
        compressed.as_slice()
    );
}

/// Test that identity (no compression) works correctly and returns the raw body.
#[tokio::test]
async fn test_identity_no_compression() {
    let plain_body = TEST_BODY.as_bytes().to_vec();
    let (url, _handle) = start_encoding_server("identity", plain_body).await;

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
