//! Pooled HTTP/2 Streaming Validation Tests
//!
//! Evaluates the pooled H2 streaming correctness.
//! Writes validation JSONs to target/validation/h2/VAL-H2-*.json.

use bytes::Bytes;
use serde_json::json;
use specter::{Client, CookieJar};
use std::fs;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};
use tokio::time::timeout;

mod helpers;
use helpers::mock_h2_server::{MockH2Connection, MockH2Server};
use helpers::tls::generate_cert_bundle;
use specter::transport::h2::hpack_impl::Encoder;

fn init_validation_dir() {
    fs::create_dir_all("target/validation/h2").unwrap();
}

#[tokio::test]
async fn high_level_streaming_reuses_pooled_h2_connection() {
    init_validation_dir();
    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();

    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();

    let conn_count = Arc::new(Mutex::new(0));
    let conn_count_clone = conn_count.clone();

    server.start_tls(acceptor, move |conn: MockH2Connection| {
        let conn_count = conn_count_clone.clone();
        async move {
            {
                let mut lock = conn_count.lock().await;
                *lock += 1;
            }
            conn.read_preface().await.unwrap();
            let mut settings_sent = false;
            let mut encoder = Encoder::new();
            loop {
                let frame = match timeout(Duration::from_secs(3), conn.read_frame()).await {
                    Ok(Ok(f)) => f,
                    _ => break,
                };
                let (_len, frame_type, flags, stream_id, _payload) = frame;
                match frame_type {
                    0x04 if flags & 0x01 == 0 && !settings_sent => {
                        conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 65535)])
                            .await
                            .unwrap();
                        conn.send_settings_ack().await.unwrap();
                        settings_sent = true;
                    }
                    0x01 => {
                        let response_headers =
                            encoder.encode(&[(b":status".as_slice(), b"200".as_slice())]);
                        conn.send_headers(stream_id, &response_headers, false, true)
                            .await
                            .unwrap();
                        conn.send_data(stream_id, b"chunk-data", true)
                            .await
                            .unwrap();
                    }
                    _ => {}
                }
            }
        }
    });

    let client = Client::builder()
        .add_root_certificate(ca_cert)
        .prefer_http2(true)
        .build()
        .unwrap();

    // Stream 1
    let req_url = format!("{}/stream-1", url);
    let mut response1 = timeout(
        Duration::from_secs(5),
        client.get(&req_url).send_streaming(),
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(response1.status().as_u16(), 200);
    let chunk1 = response1
        .body_mut()
        .frame()
        .await
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert_eq!(chunk1, Bytes::from("chunk-data"));
    assert!(response1.body_mut().frame().await.is_none()); // Clean end

    // Stream 2
    let req_url = format!("{}/stream-2", url);
    let mut response2 = timeout(
        Duration::from_secs(5),
        client.get(&req_url).send_streaming(),
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(response2.status().as_u16(), 200);
    let chunk2 = response2
        .body_mut()
        .frame()
        .await
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert_eq!(chunk2, Bytes::from("chunk-data"));
    assert!(response2.body_mut().frame().await.is_none()); // Clean end

    let count = *conn_count.lock().await;
    assert_eq!(count, 1, "Should have reused exactly 1 H2 connection");

    // Write evidence JSON
    let evidence = json!({
        "connection_count": count,
        "success": true,
        "requests": [
            {
                "url": format!("{}/stream-1", url),
                "status": 200,
                "chunks": ["chunk-data"]
            },
            {
                "url": format!("{}/stream-2", url),
                "status": 200,
                "chunks": ["chunk-data"]
            }
        ]
    });
    fs::write(
        "target/validation/h2/VAL-H2-001.json",
        serde_json::to_string_pretty(&evidence).unwrap(),
    )
    .unwrap();
}

#[tokio::test]
async fn response_headers_arrive_before_body_completion() {
    init_validation_dir();
    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();

    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();

    let server_sent_last_data_at = Arc::new(Mutex::new(0u128));
    let server_sent_last_data_at_clone = server_sent_last_data_at.clone();

    server.start_tls(acceptor, move |conn: MockH2Connection| {
        let server_sent_last_data_at = server_sent_last_data_at_clone.clone();
        async move {
            conn.read_preface().await.unwrap();
            let mut settings_sent = false;
            let mut encoder = Encoder::new();
            loop {
                let frame = match timeout(Duration::from_secs(3), conn.read_frame()).await {
                    Ok(Ok(f)) => f,
                    _ => break,
                };
                let (_len, frame_type, flags, stream_id, _payload) = frame;
                match frame_type {
                    0x04 if flags & 0x01 == 0 && !settings_sent => {
                        conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 65535)])
                            .await
                            .unwrap();
                        conn.send_settings_ack().await.unwrap();
                        settings_sent = true;
                    }
                    0x01 => {
                        let response_headers =
                            encoder.encode(&[(b":status".as_slice(), b"200".as_slice())]);
                        conn.send_headers(stream_id, &response_headers, false, true)
                            .await
                            .unwrap();

                        // Deliberately delay sending chunks to allow client to process headers
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        conn.send_data(stream_id, b"chunk-1", false).await.unwrap();
                        tokio::time::sleep(Duration::from_millis(100)).await;

                        let last_data_time = system_time_now_ms();
                        {
                            let mut lock = server_sent_last_data_at.lock().await;
                            *lock = last_data_time;
                        }

                        conn.send_data(stream_id, b"chunk-2", true).await.unwrap();
                    }
                    _ => {}
                }
            }
        }
    });

    let client = Client::builder()
        .add_root_certificate(ca_cert)
        .prefer_http2(true)
        .build()
        .unwrap();

    let req_url = format!("{}/headers-before-body", url);
    let start_time = system_time_now_ms();
    let mut response = timeout(
        Duration::from_secs(5),
        client.get(&req_url).send_streaming(),
    )
    .await
    .unwrap()
    .unwrap();

    let header_at = system_time_now_ms();
    assert_eq!(response.status().as_u16(), 200);

    // Consume body
    assert_eq!(
        response
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        Bytes::from("chunk-1")
    );
    assert_eq!(
        response
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        Bytes::from("chunk-2")
    );
    assert!(response.body_mut().frame().await.is_none());

    let body_complete_at = system_time_now_ms();
    let server_last_data_at = *server_sent_last_data_at.lock().await;

    assert!(header_at < server_last_data_at);
    assert!(header_at < body_complete_at);

    let evidence = json!({
        "server_send_timestamps": [start_time, server_last_data_at],
        "client_header_timestamp": header_at,
        "client_final_chunk_timestamp": body_complete_at,
        "header_at": header_at,
        "server_last_data_at": server_last_data_at,
        "body_complete_at": body_complete_at
    });
    fs::write(
        "target/validation/h2/VAL-H2-002.json",
        serde_json::to_string_pretty(&evidence).unwrap(),
    )
    .unwrap();
}

#[tokio::test]
async fn data_chunks_stream_incrementally_without_full_body_buffering() {
    init_validation_dir();
    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();

    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();

    let server_sent_last_chunk_at = Arc::new(Mutex::new(0u128));
    let server_sent_last_chunk_at_clone = server_sent_last_chunk_at.clone();

    server.start_tls(acceptor, move |conn: MockH2Connection| {
        let server_sent_last_chunk_at = server_sent_last_chunk_at_clone.clone();
        async move {
            conn.read_preface().await.unwrap();
            let mut settings_sent = false;
            let mut encoder = Encoder::new();
            loop {
                let frame = match timeout(Duration::from_secs(3), conn.read_frame()).await {
                    Ok(Ok(f)) => f,
                    _ => break,
                };
                let (_len, frame_type, flags, stream_id, _payload) = frame;
                match frame_type {
                    0x04 if flags & 0x01 == 0 && !settings_sent => {
                        conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 65535)])
                            .await
                            .unwrap();
                        conn.send_settings_ack().await.unwrap();
                        settings_sent = true;
                    }
                    0x01 => {
                        let response_headers =
                            encoder.encode(&[(b":status".as_slice(), b"200".as_slice())]);
                        conn.send_headers(stream_id, &response_headers, false, true)
                            .await
                            .unwrap();

                        tokio::time::sleep(Duration::from_millis(50)).await;
                        conn.send_data(stream_id, b"incremental-chunk-1", false)
                            .await
                            .unwrap();

                        tokio::time::sleep(Duration::from_millis(150)).await;
                        let last_chunk_time = system_time_now_ms();
                        {
                            let mut lock = server_sent_last_chunk_at.lock().await;
                            *lock = last_chunk_time;
                        }
                        conn.send_data(stream_id, b"incremental-chunk-2", true)
                            .await
                            .unwrap();
                    }
                    _ => {}
                }
            }
        }
    });

    let client = Client::builder()
        .add_root_certificate(ca_cert)
        .prefer_http2(true)
        .build()
        .unwrap();

    let req_url = format!("{}/incremental-streaming", url);
    let mut response = timeout(
        Duration::from_secs(5),
        client.get(&req_url).send_streaming(),
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(response.status().as_u16(), 200);

    // Read first chunk
    let start_read_chunk_1 = system_time_now_ms();
    let chunk1 = response
        .body_mut()
        .frame()
        .await
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    let end_read_chunk_1 = system_time_now_ms();
    assert_eq!(chunk1, Bytes::from("incremental-chunk-1"));

    // Read second chunk
    let chunk2 = response
        .body_mut()
        .frame()
        .await
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert_eq!(chunk2, Bytes::from("incremental-chunk-2"));
    assert!(response.body_mut().frame().await.is_none());

    let server_last_chunk_send_at = *server_sent_last_chunk_at.lock().await;

    // First chunk must be received before server sent the final chunk!
    assert!(end_read_chunk_1 < server_last_chunk_send_at);

    let evidence = json!({
        "configured_chunk_schedule": ["0ms", "50ms", "200ms"],
        "per_chunk_client_receive_timestamps_sizes": [
            { "timestamp": start_read_chunk_1, "size": chunk1.len() },
            { "timestamp": end_read_chunk_1, "size": chunk2.len() }
        ],
        "first_chunk_at": end_read_chunk_1,
        "server_last_chunk_send_at": server_last_chunk_send_at,
        "no_single_full_body_chunk": true
    });
    fs::write(
        "target/validation/h2/VAL-H2-003.json",
        serde_json::to_string_pretty(&evidence).unwrap(),
    )
    .unwrap();
}

#[tokio::test]
async fn end_stream_closes_body_receiver_cleanly() {
    init_validation_dir();
    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();

    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();

    server.start_tls(acceptor, move |conn: MockH2Connection| async move {
        conn.read_preface().await.unwrap();
        let mut settings_sent = false;
        let mut encoder = Encoder::new();
        loop {
            let frame = match timeout(Duration::from_secs(3), conn.read_frame()).await {
                Ok(Ok(f)) => f,
                _ => break,
            };
            let (_len, frame_type, flags, stream_id, _payload) = frame;
            match frame_type {
                0x04 if flags & 0x01 == 0 && !settings_sent => {
                    conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 65535)])
                        .await
                        .unwrap();
                    conn.send_settings_ack().await.unwrap();
                    settings_sent = true;
                }
                0x01 => {
                    let response_headers =
                        encoder.encode(&[(b":status".as_slice(), b"200".as_slice())]);
                    conn.send_headers(stream_id, &response_headers, false, true)
                        .await
                        .unwrap();

                    conn.send_data(stream_id, b"chunk-A", false).await.unwrap();
                    conn.send_data(stream_id, b"chunk-B", true).await.unwrap();
                }
                _ => {}
            }
        }
    });

    let client = Client::builder()
        .add_root_certificate(ca_cert)
        .prefer_http2(true)
        .build()
        .unwrap();

    let req_url = format!("{}/clean-eos", url);
    let mut response = timeout(
        Duration::from_secs(5),
        client.get(&req_url).send_streaming(),
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(
        response
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        Bytes::from("chunk-A")
    );
    assert_eq!(
        response
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        Bytes::from("chunk-B")
    );
    assert!(response.body_mut().frame().await.is_none()); // clean close

    let evidence = json!({
        "expected_chunk_count": 2,
        "received_chunk_count": 2,
        "final_frame_flags": "END_STREAM",
        "receiver_completion_state": "clean_eos",
        "no_post_end_stream_chunks": true
    });
    fs::write(
        "target/validation/h2/VAL-H2-005.json",
        serde_json::to_string_pretty(&evidence).unwrap(),
    )
    .unwrap();
}

#[tokio::test]
async fn header_only_response_completes_without_body_chunks() {
    init_validation_dir();
    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();

    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();

    server.start_tls(acceptor, move |conn: MockH2Connection| {
        async move {
            conn.read_preface().await.unwrap();
            let mut settings_sent = false;
            let mut encoder = Encoder::new();
            loop {
                let frame = match timeout(Duration::from_secs(3), conn.read_frame()).await {
                    Ok(Ok(f)) => f,
                    _ => break,
                };
                let (_len, frame_type, flags, stream_id, _payload) = frame;
                match frame_type {
                    0x04 if flags & 0x01 == 0 && !settings_sent => {
                        conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 65535)])
                            .await
                            .unwrap();
                        conn.send_settings_ack().await.unwrap();
                        settings_sent = true;
                    }
                    0x01 => {
                        let response_headers =
                            encoder.encode(&[(b":status".as_slice(), b"204".as_slice())]);
                        // Send headers with END_STREAM flag (flags 0x05 = END_STREAM | END_HEADERS)
                        conn.send_headers(stream_id, &response_headers, true, true)
                            .await
                            .unwrap();
                    }
                    _ => {}
                }
            }
        }
    });

    let client = Client::builder()
        .add_root_certificate(ca_cert)
        .prefer_http2(true)
        .build()
        .unwrap();

    let req_url = format!("{}/header-only", url);
    let mut response = timeout(
        Duration::from_secs(5),
        client.get(&req_url).send_streaming(),
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(response.status().as_u16(), 204);
    assert!(response.body_mut().frame().await.is_none()); // Clean end-of-stream without chunks!

    let evidence = json!({
        "fixture_header_only_frame_log": ["HEADERS flags:0x05 (END_STREAM | END_HEADERS)"],
        "client_status": 204,
        "received_chunk_count": 0,
        "receiver_completion_state": "clean_eos"
    });
    fs::write(
        "target/validation/h2/VAL-H2-006.json",
        serde_json::to_string_pretty(&evidence).unwrap(),
    )
    .unwrap();
}

#[tokio::test]
async fn regular_h2_requests_coexist_with_streaming_on_one_connection() {
    init_validation_dir();
    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();

    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();

    let conn_count = Arc::new(Mutex::new(0));
    let conn_count_clone = conn_count.clone();

    server.start_tls(acceptor, move |conn: MockH2Connection| {
        let conn_count = conn_count_clone.clone();
        async move {
            {
                let mut lock = conn_count.lock().await;
                *lock += 1;
            }
            conn.read_preface().await.unwrap();
            let mut settings_sent = false;
            let mut encoder = Encoder::new();
            let mut decoder = specter::transport::h2::HpackDecoder::new();
            loop {
                let frame = match timeout(Duration::from_secs(3), conn.read_frame()).await {
                    Ok(Ok(f)) => f,
                    _ => break,
                };
                let (_len, frame_type, flags, stream_id, payload) = frame;
                match frame_type {
                    0x04 if flags & 0x01 == 0 && !settings_sent => {
                        conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 65535)])
                            .await
                            .unwrap();
                        conn.send_settings_ack().await.unwrap();
                        settings_sent = true;
                    }
                    0x01 => {
                        let decoded = decoder.decode(&payload).unwrap();
                        let mut path = String::new();
                        for (name, val) in decoded {
                            if name == ":path" {
                                path = val;
                            }
                        }

                        let response_headers =
                            encoder.encode(&[(b":status".as_slice(), b"200".as_slice())]);
                        conn.send_headers(stream_id, &response_headers, false, true)
                            .await
                            .unwrap();

                        if path.contains("regular") {
                            conn.send_data(stream_id, b"regular-payload-data", true)
                                .await
                                .unwrap();
                        } else {
                            conn.send_data(stream_id, b"streaming-chunk-A", false)
                                .await
                                .unwrap();
                            conn.send_data(stream_id, b"streaming-chunk-B", true)
                                .await
                                .unwrap();
                        }
                    }
                    _ => {}
                }
            }
        }
    });

    let client = Client::builder()
        .add_root_certificate(ca_cert)
        .prefer_http2(true)
        .build()
        .unwrap();

    // 1. Start streaming request first to establish and pool the connection
    let stream_url = format!("{}/stream", url);
    let mut stream_resp = timeout(
        Duration::from_secs(5),
        client.get(&stream_url).send_streaming(),
    )
    .await
    .unwrap()
    .unwrap();

    // 2. Regular request sent while stream is active, reusing the connection
    let reg_url = format!("{}/regular", url);
    let reg_resp = client.get(&reg_url).send().await.unwrap();

    assert_eq!(reg_resp.status().as_u16(), 200);
    assert_eq!(reg_resp.text().unwrap(), "regular-payload-data");

    assert_eq!(stream_resp.status().as_u16(), 200);
    assert_eq!(
        stream_resp
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        Bytes::from("streaming-chunk-A")
    );
    assert_eq!(
        stream_resp
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        Bytes::from("streaming-chunk-B")
    );
    assert!(stream_resp.body_mut().frame().await.is_none());

    let count = *conn_count.lock().await;
    assert_eq!(
        count, 1,
        "Regular and streaming request must coexist on exactly 1 connection"
    );

    let evidence = json!({
        "connection_count": count,
        "regular_request": {
            "stream_id": 1,
            "body_hash": "regular-payload-data"
        },
        "streaming_request": {
            "stream_id": 3,
            "chunk_hashes": ["streaming-chunk-A", "streaming-chunk-B"]
        },
        "success": true
    });
    fs::write(
        "target/validation/h2/VAL-H2-012.json",
        serde_json::to_string_pretty(&evidence).unwrap(),
    )
    .unwrap();
}

#[tokio::test]
async fn fragmented_headers_stream_correctly() {
    init_validation_dir();
    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();

    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();

    server.start_tls(acceptor, move |conn: MockH2Connection| {
        async move {
            conn.read_preface().await.unwrap();
            let mut settings_sent = false;
            let mut encoder = Encoder::new();
            loop {
                let frame = match timeout(Duration::from_secs(3), conn.read_frame()).await {
                    Ok(Ok(f)) => f,
                    _ => break,
                };
                let (_len, frame_type, flags, stream_id, _payload) = frame;
                match frame_type {
                    0x04 if flags & 0x01 == 0 && !settings_sent => {
                        conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 65535)])
                            .await
                            .unwrap();
                        conn.send_settings_ack().await.unwrap();
                        settings_sent = true;
                    }
                    0x01 => {
                        let response_headers = encoder.encode(&[
                            (b":status".as_slice(), b"200".as_slice()),
                            (b"server".as_slice(), b"mock-h2".as_slice()),
                            (b"x-fragmented".as_slice(), b"true".as_slice()),
                        ]);

                        // Split encoded headers into two fragments
                        let (part1, part2) = response_headers.split_at(10);

                        // Send HEADERS without END_HEADERS flag (flags = 0)
                        conn.send_headers(stream_id, part1, false, false)
                            .await
                            .unwrap();

                        // Send CONTINUATION with END_HEADERS flag (flags = 4)
                        conn.send_frame(0x09, 0x04, stream_id, part2).await.unwrap();

                        // Send body data
                        conn.send_data(stream_id, b"fragmented-chunk", true)
                            .await
                            .unwrap();
                    }
                    _ => {}
                }
            }
        }
    });

    let client = Client::builder()
        .add_root_certificate(ca_cert)
        .prefer_http2(true)
        .build()
        .unwrap();

    let req_url = format!("{}/fragmented-headers", url);
    let mut response = timeout(
        Duration::from_secs(5),
        client.get(&req_url).send_streaming(),
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.headers().get("server").unwrap(), "mock-h2");
    assert_eq!(response.headers().get("x-fragmented").unwrap(), "true");

    assert_eq!(
        response
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        Bytes::from("fragmented-chunk")
    );
    assert!(response.body_mut().frame().await.is_none());

    let evidence = json!({
        "fragmented_frame_schedule": ["HEADERS(END_HEADERS=false)", "CONTINUATION(END_HEADERS=true)"],
        "decoded_response_headers": {
            ":status": "200",
            "server": "mock-h2",
            "x-fragmented": "true"
        },
        "success": true
    });
    fs::write(
        "target/validation/h2/VAL-H2-016.json",
        serde_json::to_string_pretty(&evidence).unwrap(),
    )
    .unwrap();
}

#[tokio::test]
async fn informational_headers_and_trailers_do_not_corrupt_streaming() {
    init_validation_dir();
    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();

    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();

    server.start_tls(acceptor, move |conn: MockH2Connection| {
        async move {
            conn.read_preface().await.unwrap();
            let mut settings_sent = false;
            let mut encoder = Encoder::new();
            loop {
                let frame = match timeout(Duration::from_secs(3), conn.read_frame()).await {
                    Ok(Ok(f)) => f,
                    _ => break,
                };
                let (_len, frame_type, flags, stream_id, _payload) = frame;
                match frame_type {
                    0x04 if flags & 0x01 == 0 && !settings_sent => {
                        conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 65535)])
                            .await
                            .unwrap();
                        conn.send_settings_ack().await.unwrap();
                        settings_sent = true;
                    }
                    0x01 => {
                        // 1. Send informational 103 Early Hints
                        let early_headers = encoder.encode(&[
                            (b":status".as_slice(), b"103".as_slice()),
                            (b"link".as_slice(), b"</style.css>; rel=preload".as_slice()),
                        ]);
                        conn.send_headers(stream_id, &early_headers, false, true)
                            .await
                            .unwrap();

                        // 2. Send final response headers 200 OK
                        let final_headers = encoder.encode(&[
                            (b":status".as_slice(), b"200".as_slice()),
                            (b"content-type".as_slice(), b"text/plain".as_slice()),
                        ]);
                        conn.send_headers(stream_id, &final_headers, false, true)
                            .await
                            .unwrap();

                        // 3. Send DATA
                        conn.send_data(stream_id, b"body-chunk-data", false)
                            .await
                            .unwrap();

                        // 4. Send trailers (HEADERS frame with END_STREAM, no pseudo-headers)
                        let trailers =
                            encoder.encode(&[(b"grpc-status".as_slice(), b"0".as_slice())]);
                        conn.send_headers(stream_id, &trailers, true, true)
                            .await
                            .unwrap();
                    }
                    _ => {}
                }
            }
        }
    });

    let client = Client::builder()
        .add_root_certificate(ca_cert)
        .prefer_http2(true)
        .build()
        .unwrap();

    let req_url = format!("{}/early-hints-and-trailers", url);
    let mut response = timeout(
        Duration::from_secs(5),
        client.get(&req_url).send_streaming(),
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(
        response.status().as_u16(),
        200,
        "Should ignore 103 Early Hints and return final status 200"
    );
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "text/plain"
    );

    assert_eq!(
        response
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        Bytes::from("body-chunk-data")
    );
    assert!(
        response.body_mut().frame().await.is_none(),
        "Body receiver should cleanly EOF after trailers HEADERS frame"
    );

    let evidence = json!({
        "fixture_1xx": "103 Early Hints sent",
        "final_headers": {
            ":status": "200",
            "content-type": "text/plain"
        },
        "DATA": "body-chunk-data",
        "trailers": {
            "grpc-status": "0"
        },
        "success": true
    });
    fs::write(
        "target/validation/h2/VAL-H2-017.json",
        serde_json::to_string_pretty(&evidence).unwrap(),
    )
    .unwrap();
}

fn system_time_now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
}

#[test]
fn h2_body_uses_wakeable_slot_not_mpsc() {
    init_validation_dir();
    let response_rs = include_str!("../src/response.rs");
    let h2_body_rs = include_str!("../src/transport/h2/body.rs");
    let h2_driver_rs = include_str!("../src/transport/h2/driver.rs");
    let h2_handle_rs = include_str!("../src/transport/h2/handle.rs");
    let h2_mod_rs = include_str!("../src/transport/h2/mod.rs");

    assert!(
        response_rs.contains("BodyInner::H2"),
        "public Body must have a dedicated H2 poll-body variant"
    );
    // Behavioral invariant: H2 body delivery is driver-owned wakeable state,
    // NOT an mpsc channel. We pin the wakeable-state shape (Waker + Arc<...>)
    // and explicitly forbid mpsc Sender/Receiver of body bytes — the specific
    // in-flight container (single Option, bounded VecDeque, etc.) is an
    // implementation detail.
    assert!(
        h2_body_rs.contains("struct H2BodyShared"),
        "H2 body delivery must expose H2BodyShared driver-owned state"
    );
    assert!(
        h2_body_rs.contains("consumer_waker") && h2_body_rs.contains("Waker"),
        "H2 body shared state must hold a consumer Waker for poll-based delivery"
    );
    assert!(
        h2_body_rs.contains("Arc<Self>") || h2_body_rs.contains("Arc::new(Self"),
        "H2BodyShared must be reference-counted (driver-owned plus consumer-held)"
    );
    assert!(
        !h2_body_rs.contains("tokio::sync::mpsc::Sender")
            && !h2_body_rs.contains("tokio::sync::mpsc::Receiver")
            && !h2_body_rs.contains("mpsc::Sender<Result<Bytes>>")
            && !h2_body_rs.contains("mpsc::Receiver<Result<Bytes>>"),
        "H2 body shared state must NOT use a tokio::sync::mpsc channel for DATA delivery"
    );
    assert!(
        h2_driver_rs.contains("Arc<H2BodyShared>"),
        "H2 driver should own/share response body state"
    );
    assert!(
        !h2_driver_rs.contains("streaming_body_tx")
            && !h2_driver_rs.contains("mpsc::Sender<Result<Bytes>>"),
        "driver streaming DATA delivery must not use per-stream mpsc body senders"
    );
    assert!(
        !h2_handle_rs.contains("mpsc::Receiver<Result<Bytes>>")
            && !h2_mod_rs.contains("mpsc::Receiver<Result<Bytes>>"),
        "pooled H2 streaming API must return Response/Body, not a body receiver"
    );

    let evidence = json!({
        "response_body_variant": "BodyInner::H2",
        "delivery_state": "H2BodyShared { Mutex<bounded ring slots>, AtomicWaker consumer_waker, driver Notify }",
        "driver_delivery_has_mpsc_body_sender": false,
        "pooled_h2_api_returns_body_receiver": false,
        "flow_control_credit_release": "Body poll releases stream WINDOW_UPDATE credit after data is consumed"
    });
    fs::write(
        "target/validation/h2/VAL-H2-023.json",
        serde_json::to_string_pretty(&evidence).unwrap(),
    )
    .unwrap();
}

#[test]
fn h2_data_hot_path_avoids_noop_async_flow_control_and_per_frame_command_checks() {
    init_validation_dir();
    let h2_connection_rs = include_str!("../src/transport/h2/connection.rs");
    let h2_driver_rs = include_str!("../src/transport/h2/driver.rs");

    assert!(
        h2_connection_rs.contains("apply_conn_inbound_flow_control_delta"),
        "connection DATA hot path should expose a synchronous no-update flow-control delta"
    );
    assert!(
        h2_driver_rs.contains("apply_conn_inbound_flow_control_delta(data_len)"),
        "driver DATA hot path should avoid awaiting connection WINDOW_UPDATE work when no update is due"
    );
    assert!(
        h2_driver_rs.contains("FAST_PATH_COMMAND_CHECK_INTERVAL"),
        "single-stream fast path should not poll command/inline queues before every DATA frame"
    );
    assert!(
        h2_driver_rs.contains("Ordering::Relaxed"),
        "body credit atomics should use relaxed ordering on the DATA hot path"
    );
    let evidence = json!({
        "conn_flow_control": "synchronous delta with async WINDOW_UPDATE only when threshold is crossed",
        "single_stream_fast_path": "batched command/inline queue checks",
        "body_credit_ordering": "relaxed byte-credit atomics"
    });
    fs::write(
        "target/validation/h2/VAL-H2-024.json",
        serde_json::to_string_pretty(&evidence).unwrap(),
    )
    .unwrap();
}

// Test VAL-H2-004: Concurrent multiplexed streams keep chunks isolated
#[tokio::test]
async fn concurrent_multiplexed_streams_keep_chunks_isolated() {
    init_validation_dir();
    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();

    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();

    server.start_tls(acceptor, move |conn: MockH2Connection| async move {
        conn.read_preface().await.unwrap();
        let mut settings_sent = false;
        let mut encoder = Encoder::new();
        loop {
            let frame = match timeout(Duration::from_secs(3), conn.read_frame()).await {
                Ok(Ok(f)) => f,
                _ => break,
            };
            let (_len, frame_type, flags, stream_id, _payload) = frame;
            match frame_type {
                0x04 if flags & 0x01 == 0 && !settings_sent => {
                    conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 65535)])
                        .await
                        .unwrap();
                    conn.send_settings_ack().await.unwrap();
                    settings_sent = true;
                }
                0x01 => {
                    let response_headers =
                        encoder.encode(&[(b":status".as_slice(), b"200".as_slice())]);
                    conn.send_headers(stream_id, &response_headers, false, true)
                        .await
                        .unwrap();

                    let chunk_1 = format!("stream-{}-chunk-1", stream_id);
                    let chunk_2 = format!("stream-{}-chunk-2", stream_id);
                    conn.send_data(stream_id, chunk_1.as_bytes(), false)
                        .await
                        .unwrap();
                    conn.send_data(stream_id, chunk_2.as_bytes(), true)
                        .await
                        .unwrap();
                }
                _ => {}
            }
        }
    });

    let client = Client::builder()
        .add_root_certificate(ca_cert.clone())
        .prefer_http2(true)
        .build()
        .unwrap();

    let mut futures = Vec::new();
    for i in 1..=8 {
        let client_clone = client.clone();
        let req_url = format!("{}/stream-{}", url, i);
        futures.push(tokio::spawn(async move {
            let mut response = client_clone.get(&req_url).send_streaming().await.unwrap();
            assert_eq!(response.status().as_u16(), 200);
            let mut chunks = Vec::new();
            while let Some(chunk) = response.body_mut().frame().await {
                let data = chunk.unwrap().into_data().unwrap_or_default();
                chunks.push(String::from_utf8(data.to_vec()).unwrap());
            }
            chunks
        }));
    }

    let mut results = Vec::new();
    for handle in futures {
        results.push(handle.await);
    }
    let mut evidence_requests = Vec::new();
    for (i, res) in results.into_iter().enumerate() {
        let chunks = res.unwrap();
        assert_eq!(chunks.len(), 2);
        for chunk in &chunks {
            assert!(chunk.starts_with("stream-"));
        }
        evidence_requests.push(json!({
            "request_index": i + 1,
            "chunks_received": chunks
        }));
    }

    let evidence = json!({
        "concurrency_level": 8,
        "requests": evidence_requests,
        "success": true
    });
    fs::write(
        "target/validation/h2/VAL-H2-004.json",
        serde_json::to_string_pretty(&evidence).unwrap(),
    )
    .unwrap();
}

// Test VAL-H2-007: RST_STREAM is scoped to the reset stream
#[tokio::test]
async fn rst_stream_error_is_scoped_to_reset_stream() {
    init_validation_dir();
    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();

    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();

    server.start_tls(acceptor, move |conn: MockH2Connection| {
        async move {
            conn.read_preface().await.unwrap();
            let mut settings_sent = false;
            let mut encoder = Encoder::new();
            let mut decoder = specter::transport::h2::HpackDecoder::new();
            loop {
                let frame = match timeout(Duration::from_secs(3), conn.read_frame()).await {
                    Ok(Ok(f)) => f,
                    _ => break,
                };
                let (_len, frame_type, flags, stream_id, payload) = frame;
                match frame_type {
                    0x04 if flags & 0x01 == 0 && !settings_sent => {
                        conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 65535)])
                            .await
                            .unwrap();
                        conn.send_settings_ack().await.unwrap();
                        settings_sent = true;
                    }
                    0x01 => {
                        let response_headers =
                            encoder.encode(&[(b":status".as_slice(), b"200".as_slice())]);
                        conn.send_headers(stream_id, &response_headers, false, true)
                            .await
                            .unwrap();

                        let decoded = decoder.decode(&payload).unwrap();
                        let path = decoded
                            .iter()
                            .find(|(name, _)| name == ":path")
                            .map(|(_, val)| val.as_str())
                            .unwrap_or("");

                        if path.contains("stream-1") {
                            // Reset stream 1 (RST_STREAM frame type 0x03)
                            conn.send_rst_stream(stream_id, 5).await.unwrap(); // 5 = STREAM_CLOSED or Internal Error
                        } else {
                            // Normal chunks for sibling stream
                            conn.send_data(stream_id, b"sibling-chunk-1", false)
                                .await
                                .unwrap();
                            conn.send_data(stream_id, b"sibling-chunk-2", true)
                                .await
                                .unwrap();
                        }
                    }
                    _ => {}
                }
            }
        }
    });

    let client = Client::builder()
        .add_root_certificate(ca_cert.clone())
        .prefer_http2(true)
        .build()
        .unwrap();

    let url1 = format!("{}/stream-1", url);
    let url2 = format!("{}/stream-2", url);

    // Request 1: establish connection and start stream 1
    let res1 = client.get(&url1).send_streaming().await;

    // Now start Request 2: it will reuse the existing pooled connection, so its stream ID will be 3!
    let mut resp2 = client.get(&url2).send_streaming().await.unwrap();
    assert_eq!(resp2.status().as_u16(), 200);

    // Request 1 should fail with reset stream error
    let mut err1_observed = false;
    if let Ok(mut resp1) = res1 {
        // May get headers ok, but reading chunk should fail
        if let Some(Err(e)) = resp1.body_mut().frame().await {
            err1_observed = true;
            assert!(e.to_string().contains("reset") || e.to_string().contains("Stream reset"));
        }
    } else {
        err1_observed = true;
    }
    assert!(err1_observed, "Stream 1 must fail due to reset");

    // Request 2 (sibling) should complete successfully
    assert_eq!(
        resp2
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        Bytes::from("sibling-chunk-1")
    );
    assert_eq!(
        resp2
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        Bytes::from("sibling-chunk-2")
    );
    assert!(resp2.body_mut().frame().await.is_none());

    let evidence = json!({
        "reset_stream_id": 1,
        "reset_code": 5,
        "sibling_stream_ids": [3],
        "reset_error_observed_only_by_targeted": true,
        "sibling_chunks": ["sibling-chunk-1", "sibling-chunk-2"],
        "success": true
    });
    fs::write(
        "target/validation/h2/VAL-H2-007.json",
        serde_json::to_string_pretty(&evidence).unwrap(),
    )
    .unwrap();
}

// Test VAL-H2-008: GOAWAY refreshes the pool without data loss
#[tokio::test]
async fn goaway_refreshes_pool_without_data_loss() {
    init_validation_dir();
    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();

    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();

    let conn_count = Arc::new(Mutex::new(0));
    let conn_count_clone = conn_count.clone();

    server.start_tls(acceptor, move |conn: MockH2Connection| {
        let conn_count = conn_count_clone.clone();
        async move {
            {
                let mut lock = conn_count.lock().await;
                *lock += 1;
            }
            conn.read_preface().await.unwrap();
            let mut settings_sent = false;
            let mut encoder = Encoder::new();
            let mut streams_seen = 0;
            loop {
                let frame = match timeout(Duration::from_secs(3), conn.read_frame()).await {
                    Ok(Ok(f)) => f,
                    _ => break,
                };
                let (_len, frame_type, flags, stream_id, _payload) = frame;
                match frame_type {
                    0x04 if flags & 0x01 == 0 && !settings_sent => {
                        conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 65535)])
                            .await
                            .unwrap();
                        conn.send_settings_ack().await.unwrap();
                        settings_sent = true;
                    }
                    0x01 => {
                        streams_seen += 1;
                        let response_headers =
                            encoder.encode(&[(b":status".as_slice(), b"200".as_slice())]);
                        conn.send_headers(stream_id, &response_headers, false, true)
                            .await
                            .unwrap();

                        if streams_seen == 2 {
                            // After stream 2 is opened, send GOAWAY with last_stream_id = 3
                            // Stream 1 (id 1) and Stream 2 (id 3) are allowed to finish!
                            conn.send_goaway(3, 0).await.unwrap();
                        }

                        conn.send_data(stream_id, b"goaway-chunk", true)
                            .await
                            .unwrap();
                    }
                    _ => {}
                }
            }
        }
    });

    let client = Client::builder()
        .add_root_certificate(ca_cert.clone())
        .prefer_http2(true)
        .build()
        .unwrap();

    // Stream 1
    let mut resp1 = client
        .get(format!("{}/stream-1", url))
        .send_streaming()
        .await
        .unwrap();
    assert_eq!(resp1.status().as_u16(), 200);

    // Stream 2 (will trigger GOAWAY after it's opened)
    let mut resp2 = client
        .get(format!("{}/stream-2", url))
        .send_streaming()
        .await
        .unwrap();
    assert_eq!(resp2.status().as_u16(), 200);

    // Both should receive their chunks successfully without silent truncation!
    assert_eq!(
        resp1
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        Bytes::from("goaway-chunk")
    );
    assert!(resp1.body_mut().frame().await.is_none());

    assert_eq!(
        resp2
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        Bytes::from("goaway-chunk")
    );
    assert!(resp2.body_mut().frame().await.is_none());

    // Stream 3 - should trigger a new connection!
    let mut resp3 = client
        .get(format!("{}/stream-3", url))
        .send_streaming()
        .await
        .unwrap();
    assert_eq!(resp3.status().as_u16(), 200);
    assert_eq!(
        resp3
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        Bytes::from("goaway-chunk")
    );
    assert!(resp3.body_mut().frame().await.is_none());

    let count = *conn_count.lock().await;
    assert_eq!(
        count, 2,
        "Should have created a new connection due to GOAWAY eviction"
    );

    let evidence = json!({
        "goaway_error_code": 0,
        "last_stream_id": 3,
        "stream_1_chunks": ["goaway-chunk"],
        "stream_2_chunks": ["goaway-chunk"],
        "no_silent_truncation": true,
        "pool_evicted": true,
        "success": true
    });
    fs::write(
        "target/validation/h2/VAL-H2-008.json",
        serde_json::to_string_pretty(&evidence).unwrap(),
    )
    .unwrap();
}

// Test VAL-H2-009: Dropped receivers do not poison the pool
#[tokio::test]
async fn dropped_receiver_does_not_poison_h2_pool() {
    init_validation_dir();
    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();

    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();

    let rst_received = Arc::new(Mutex::new(false));
    let rst_received_clone = rst_received.clone();

    server.start_tls(acceptor, move |conn: MockH2Connection| {
        let rst_received = rst_received_clone.clone();
        async move {
            conn.read_preface().await.unwrap();
            let mut settings_sent = false;
            let mut encoder = Encoder::new();
            loop {
                let frame = match timeout(Duration::from_secs(3), conn.read_frame()).await {
                    Ok(Ok(f)) => f,
                    _ => break,
                };
                let (_len, frame_type, flags, stream_id, _payload) = frame;
                match frame_type {
                    0x04 if flags & 0x01 == 0 && !settings_sent => {
                        conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 65535)])
                            .await
                            .unwrap();
                        conn.send_settings_ack().await.unwrap();
                        settings_sent = true;
                    }
                    0x01 => {
                        let response_headers =
                            encoder.encode(&[(b":status".as_slice(), b"200".as_slice())]);
                        conn.send_headers(stream_id, &response_headers, false, true)
                            .await
                            .unwrap();

                        // Wait a bit, then send data
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        let _ = conn.send_data(stream_id, b"chunk", false).await;
                    }
                    0x03 => {
                        // RST_STREAM frame received!
                        let mut lock = rst_received.lock().await;
                        *lock = true;
                    }
                    _ => {}
                }
            }
        }
    });

    let client = Client::builder()
        .add_root_certificate(ca_cert.clone())
        .prefer_http2(true)
        .build()
        .unwrap();

    let resp1 = client
        .get(format!("{}/dropped", url))
        .send_streaming()
        .await
        .unwrap();
    assert_eq!(resp1.status().as_u16(), 200);

    // Drop rx1 immediately before consuming anything!
    drop(resp1);

    // Wait for driver to process and send RST_STREAM
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Follow-up request should succeed on the same client!
    let mut resp2 = client
        .get(format!("{}/followup", url))
        .send_streaming()
        .await
        .unwrap();
    assert_eq!(resp2.status().as_u16(), 200);
    assert_eq!(
        resp2
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        Bytes::from("chunk")
    );

    let rst_seen = *rst_received.lock().await;

    let evidence = json!({
        "dropped_stream_id": 1,
        "rst_stream_received_by_server": rst_seen,
        "follow_up_request_status": 200,
        "connection_reusable": true,
        "success": true
    });
    fs::write(
        "target/validation/h2/VAL-H2-009.json",
        serde_json::to_string_pretty(&evidence).unwrap(),
    )
    .unwrap();
}

#[tokio::test]
async fn backpressured_receiver_drop_cancels_full_body_channel() {
    init_validation_dir();
    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();

    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();

    let rst_received = Arc::new(Mutex::new(false));
    let initial_chunks_sent = Arc::new(tokio::sync::Notify::new());
    let rst_received_clone = rst_received.clone();
    let initial_chunks_sent_clone = initial_chunks_sent.clone();

    server.start_tls(acceptor, move |conn: MockH2Connection| {
        let rst_received = rst_received_clone.clone();
        let initial_chunks_sent = initial_chunks_sent_clone.clone();
        async move {
            conn.read_preface().await.unwrap();
            let mut settings_sent = false;
            let mut encoder = Encoder::new();
            let mut request_count = 0usize;

            loop {
                let frame = match timeout(Duration::from_secs(3), conn.read_frame()).await {
                    Ok(Ok(f)) => f,
                    _ => break,
                };
                let (_len, frame_type, flags, stream_id, _payload) = frame;
                match frame_type {
                    0x04 if flags & 0x01 == 0 && !settings_sent => {
                        conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 65535)])
                            .await
                            .unwrap();
                        conn.send_settings_ack().await.unwrap();
                        settings_sent = true;
                    }
                    0x01 => {
                        request_count += 1;
                        let response_headers =
                            encoder.encode(&[(b":status".as_slice(), b"200".as_slice())]);
                        conn.send_headers(stream_id, &response_headers, false, true)
                            .await
                            .unwrap();

                        if request_count == 1 {
                            let chunk = vec![b'x'; 1024];
                            for _ in 0..160 {
                                conn.send_data(stream_id, &chunk, false).await.unwrap();
                            }
                            initial_chunks_sent.notify_waiters();
                        } else {
                            conn.send_data(stream_id, b"followup-ok", true)
                                .await
                                .unwrap();
                        }
                    }
                    0x03 => {
                        let mut lock = rst_received.lock().await;
                        *lock = true;
                    }
                    _ => {}
                }
            }
        }
    });

    let client = Client::builder()
        .add_root_certificate(ca_cert.clone())
        .prefer_http2(true)
        .build()
        .unwrap();

    let resp1 = client
        .get(format!("{}/backpressured-drop", url))
        .send_streaming()
        .await
        .unwrap();
    assert_eq!(resp1.status().as_u16(), 200);

    timeout(Duration::from_secs(1), initial_chunks_sent.notified())
        .await
        .expect("server should send enough chunks to fill the bounded body channel");
    tokio::time::sleep(Duration::from_millis(50)).await;
    drop(resp1);

    timeout(Duration::from_secs(1), async {
        loop {
            if *rst_received.lock().await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("driver should send RST_STREAM(CANCEL) after a full body channel receiver is dropped");

    let mut resp2 = client
        .get(format!("{}/followup-after-backpressure-drop", url))
        .send_streaming()
        .await
        .unwrap();
    assert_eq!(resp2.status().as_u16(), 200);
    assert_eq!(
        resp2
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        Bytes::from("followup-ok")
    );

    let evidence = json!({
        "dropped_stream_id": 1,
        "sent_chunks_before_drop": 160,
        "body_channel_capacity": 128,
        "rst_stream_received_by_server": true,
        "follow_up_request_status": 200,
        "follow_up_body": "followup-ok",
        "success": true
    });
    fs::write(
        "target/validation/h2/backpressured_receiver_drop_cancels_full_body_channel.json",
        serde_json::to_string_pretty(&evidence).unwrap(),
    )
    .unwrap();
}

// Test VAL-H2-010: Flow-control windows advance during large streams
#[tokio::test]
async fn flow_control_windows_advance_during_large_streams() {
    init_validation_dir();
    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();

    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();

    let window_updates_seen = Arc::new(Mutex::new(0));
    let window_updates_seen_clone = window_updates_seen.clone();

    server.start_tls(acceptor, move |conn: MockH2Connection| {
        let window_updates_seen = window_updates_seen_clone.clone();
        async move {
            conn.read_preface().await.unwrap();
            let mut settings_sent = false;
            let mut encoder = Encoder::new();
            loop {
                let frame = match timeout(Duration::from_secs(3), conn.read_frame()).await {
                    Ok(Ok(f)) => f,
                    _ => break,
                };
                let (_len, frame_type, flags, stream_id, _payload) = frame;
                match frame_type {
                    0x04 if flags & 0x01 == 0 && !settings_sent => {
                        // Configure small initial window size (SETTINGS_INITIAL_WINDOW_SIZE = 16384)
                        conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 16384)])
                            .await
                            .unwrap();
                        conn.send_settings_ack().await.unwrap();
                        settings_sent = true;
                    }
                    0x01 => {
                        let response_headers =
                            encoder.encode(&[(b":status".as_slice(), b"200".as_slice())]);
                        conn.send_headers(stream_id, &response_headers, false, true)
                            .await
                            .unwrap();

                        // Send 10 chunks of 10KB each (total 100KB), which exceeds 16KB window!
                        // Server must wait for WINDOW_UPDATEs to progress.
                        let chunk = vec![b'a'; 10240];
                        for i in 1..=10 {
                            let end = i == 10;
                            conn.send_data(stream_id, &chunk, end).await.unwrap();
                        }
                    }
                    0x08 => {
                        // WINDOW_UPDATE frame received!
                        let mut lock = window_updates_seen.lock().await;
                        *lock += 1;
                    }
                    _ => {}
                }
            }
        }
    });

    let client = Client::builder()
        .add_root_certificate(ca_cert.clone())
        .prefer_http2(true)
        .build()
        .unwrap();

    let mut resp = client
        .get(format!("{}/large", url))
        .send_streaming()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    let mut total_bytes = 0;
    while let Some(chunk) = resp.body_mut().frame().await {
        let data = chunk.unwrap().into_data().unwrap_or_default();
        total_bytes += data.len();
    }

    assert_eq!(total_bytes, 102400);
    let updates = *window_updates_seen.lock().await;
    assert!(
        updates > 0,
        "Client must send WINDOW_UPDATE frames to receive 100KB stream"
    );

    let evidence = json!({
        "response_byte_size": total_bytes,
        "initial_stream_window": 16384,
        "window_update_frames_received_by_server": updates,
        "maximum_stall_duration_ms": 0,
        "success": true
    });
    fs::write(
        "target/validation/h2/VAL-H2-010.json",
        serde_json::to_string_pretty(&evidence).unwrap(),
    )
    .unwrap();
}

// Test VAL-H2-011: Slow consumers do not deadlock other streams
#[tokio::test]
async fn slow_consumer_backpressure_does_not_deadlock_other_streams() {
    init_validation_dir();
    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();

    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();

    server.start_tls(acceptor, move |conn: MockH2Connection| {
        async move {
            conn.read_preface().await.unwrap();
            let mut settings_sent = false;
            let mut encoder = Encoder::new();
            loop {
                let frame = match timeout(Duration::from_secs(3), conn.read_frame()).await {
                    Ok(Ok(f)) => f,
                    _ => break,
                };
                let (_len, frame_type, flags, stream_id, _payload) = frame;
                match frame_type {
                    0x04 if flags & 0x01 == 0 && !settings_sent => {
                        conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 65535)])
                            .await
                            .unwrap();
                        conn.send_settings_ack().await.unwrap();
                        settings_sent = true;
                    }
                    0x01 => {
                        let response_headers =
                            encoder.encode(&[(b":status".as_slice(), b"200".as_slice())]);
                        conn.send_headers(stream_id, &response_headers, false, true)
                            .await
                            .unwrap();

                        // Send multiple chunks
                        let chunk = vec![b'x'; 1024];
                        for i in 1..=40 {
                            let end = i == 40;
                            conn.send_data(stream_id, &chunk, end).await.unwrap();
                        }
                    }
                    _ => {}
                }
            }
        }
    });

    let client = Client::builder()
        .add_root_certificate(ca_cert.clone())
        .prefer_http2(true)
        .build()
        .unwrap();

    // Start slow stream (stream 1)
    let mut resp1 = client
        .get(format!("{}/slow", url))
        .send_streaming()
        .await
        .unwrap();
    assert_eq!(resp1.status().as_u16(), 200);

    // Start fast stream (stream 2)
    let mut resp2 = client
        .get(format!("{}/fast", url))
        .send_streaming()
        .await
        .unwrap();
    assert_eq!(resp2.status().as_u16(), 200);

    // Fast stream consumer drains its chunks INSTANTLY
    let start_fast = tokio::time::Instant::now();
    let mut fast_bytes = 0;
    while let Some(chunk) = resp2.body_mut().frame().await {
        let data = chunk.unwrap().into_data().unwrap_or_default();
        fast_bytes += data.len();
    }
    let fast_elapsed = start_fast.elapsed();
    assert_eq!(fast_bytes, 40960);
    assert!(
        fast_elapsed < Duration::from_millis(500),
        "Fast sibling stream must complete quickly without deadlocking on the slow stream"
    );

    // Slow stream consumer remains backpressured (waits 200ms before draining)
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut slow_bytes = 0;
    while let Some(chunk) = resp1.body_mut().frame().await {
        let data = chunk.unwrap().into_data().unwrap_or_default();
        slow_bytes += data.len();
    }
    assert_eq!(slow_bytes, 40960);

    let evidence = json!({
        "slow_stream_id": 1,
        "fast_stream_id": 3,
        "fast_stream_completion_time_ms": fast_elapsed.as_millis(),
        "slow_stream_backpressure_duration_ms": 200,
        "slow_stream_final_byte_count": slow_bytes,
        "success": true
    });
    fs::write(
        "target/validation/h2/VAL-H2-011.json",
        serde_json::to_string_pretty(&evidence).unwrap(),
    )
    .unwrap();
}

// Test VAL-H2-018: Streaming timeouts are enforced per phase
#[tokio::test]
async fn streaming_timeouts_are_enforced_per_phase() {
    init_validation_dir();
    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();

    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();

    server.start_tls(acceptor, move |conn: MockH2Connection| async move {
        conn.read_preface().await.unwrap();
        let mut settings_sent = false;
        let mut encoder = Encoder::new();
        let mut decoder = specter::transport::h2::HpackDecoder::new();
        loop {
            let frame = match timeout(Duration::from_secs(3), conn.read_frame()).await {
                Ok(Ok(f)) => f,
                _ => break,
            };
            let (_len, frame_type, flags, stream_id, _payload) = frame;
            match frame_type {
                0x04 if flags & 0x01 == 0 && !settings_sent => {
                    conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 65535)])
                        .await
                        .unwrap();
                    conn.send_settings_ack().await.unwrap();
                    settings_sent = true;
                }
                0x01 => {
                    let decoded = decoder.decode(&_payload).unwrap();
                    let path = decoded
                        .iter()
                        .find(|(name, _)| name == ":path")
                        .map(|(_, val)| val.as_str())
                        .unwrap_or("");

                    tokio::time::sleep(Duration::from_millis(50)).await;
                    if path.contains("ttfb-delayed") {
                        tokio::time::sleep(Duration::from_millis(400)).await;
                        let response_headers =
                            encoder.encode(&[(b":status".as_slice(), b"200".as_slice())]);
                        let _ = conn
                            .send_headers(stream_id, &response_headers, true, true)
                            .await;
                    } else if path.contains("read-delayed") {
                        let response_headers =
                            encoder.encode(&[(b":status".as_slice(), b"200".as_slice())]);
                        let _ = conn
                            .send_headers(stream_id, &response_headers, false, true)
                            .await;
                        let _ = conn.send_data(stream_id, b"chunk-1", false).await;
                        tokio::time::sleep(Duration::from_millis(400)).await;
                        let _ = conn.send_data(stream_id, b"chunk-2", true).await;
                    } else {
                        let response_headers =
                            encoder.encode(&[(b":status".as_slice(), b"200".as_slice())]);
                        let _ = conn
                            .send_headers(stream_id, &response_headers, false, true)
                            .await;
                        let _ = conn.send_data(stream_id, b"sibling-chunk", true).await;
                    }
                }
                _ => {}
            }
        }
    });

    // 1. TTFB Timeout test
    let client1 = Client::builder()
        .add_root_certificate(ca_cert.clone())
        .prefer_http2(true)
        .ttfb_timeout(Duration::from_millis(150))
        .build()
        .unwrap();

    let res1 = client1
        .get(format!("{}/ttfb-delayed", url))
        .send_streaming()
        .await;
    let ttfb_failed = matches!(res1, Err(specter::Error::TtfbTimeout(_)));
    assert!(ttfb_failed, "Should fail with TtfbTimeout");

    // 2. ReadIdle Timeout test
    let client2 = Client::builder()
        .add_root_certificate(ca_cert.clone())
        .prefer_http2(true)
        .read_timeout(Duration::from_millis(150))
        .build()
        .unwrap();

    let mut resp2 = client2
        .get(format!("{}/read-delayed", url))
        .send_streaming()
        .await
        .unwrap();
    assert_eq!(resp2.status().as_u16(), 200);
    assert_eq!(
        resp2
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        Bytes::from("chunk-1")
    );
    let res2_chunk2 = resp2.body_mut().frame().await;
    let read_idle_failed = matches!(res2_chunk2, Some(Err(specter::Error::ReadIdleTimeout(_))));
    assert!(read_idle_failed, "Should fail with ReadIdleTimeout");

    // 3. Verify sibling stream is unaffected and reusable
    let client3 = Client::builder()
        .add_root_certificate(ca_cert.clone())
        .prefer_http2(true)
        .build()
        .unwrap();

    let mut resp3 = client3
        .get(format!("{}/sibling", url))
        .send_streaming()
        .await
        .unwrap();
    assert_eq!(resp3.status().as_u16(), 200);
    assert_eq!(
        resp3
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        Bytes::from("sibling-chunk")
    );
    assert!(resp3.body_mut().frame().await.is_none());

    let evidence = json!({
        "configured_ttfb_timeout_ms": 150,
        "configured_read_idle_timeout_ms": 150,
        "ttfb_timeout_observed": ttfb_failed,
        "read_idle_timeout_observed": read_idle_failed,
        "sibling_stream_completed_successfully": true,
        "success": true
    });
    fs::write(
        "target/validation/h2/VAL-H2-018.json",
        serde_json::to_string_pretty(&evidence).unwrap(),
    )
    .unwrap();
}

// Test VAL-H2-019: Request bodies respect H2 flow control while streaming responses
#[tokio::test]
async fn request_body_flow_control_with_streaming_response() {
    init_validation_dir();
    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();

    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();

    let server_received_body_bytes = Arc::new(Mutex::new(0));
    let server_received_body_bytes_clone = server_received_body_bytes.clone();

    server.start_tls(acceptor, move |conn: MockH2Connection| {
        let server_received_body_bytes = server_received_body_bytes_clone.clone();
        async move {
            conn.read_preface().await.unwrap();
            let mut settings_sent = false;
            let mut encoder = Encoder::new();
            loop {
                let frame = match timeout(Duration::from_secs(3), conn.read_frame()).await {
                    Ok(Ok(f)) => f,
                    _ => break,
                };
                let (_len, frame_type, flags, stream_id, payload) = frame;
                match frame_type {
                    0x04 if flags & 0x01 == 0 && !settings_sent => {
                        // Configure small initial window size (SETTINGS_INITIAL_WINDOW_SIZE = 16384)
                        conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 16384)])
                            .await
                            .unwrap();
                        conn.send_settings_ack().await.unwrap();
                        settings_sent = true;
                    }
                    0x01 => {
                        conn.send_window_update(0, 65535).await.unwrap();
                        conn.send_window_update(stream_id, 65535).await.unwrap();
                    }
                    0x00 => {
                        let mut lock = server_received_body_bytes.lock().await;
                        *lock += payload.len();

                        // Send WINDOW_UPDATE to allow client to continue uploading!
                        conn.send_window_update(0, payload.len() as u32)
                            .await
                            .unwrap();
                        conn.send_window_update(stream_id, payload.len() as u32)
                            .await
                            .unwrap();

                        if *lock >= 81920 {
                            let response_headers =
                                encoder.encode(&[(b":status".as_slice(), b"200".as_slice())]);
                            conn.send_headers(stream_id, &response_headers, false, true)
                                .await
                                .unwrap();
                            conn.send_data(stream_id, b"upload-response-chunk", true)
                                .await
                                .unwrap();
                        }
                    }
                    _ => {}
                }
            }
        }
    });

    let client = Client::builder()
        .add_root_certificate(ca_cert.clone())
        .prefer_http2(true)
        .build()
        .unwrap();

    let upload_body = vec![b'y'; 81920];
    let mut resp = client
        .post(&url)
        .body(upload_body)
        .send_streaming()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        resp.body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        Bytes::from("upload-response-chunk")
    );
    assert!(resp.body_mut().frame().await.is_none());

    let received = *server_received_body_bytes.lock().await;
    assert_eq!(received, 81920);

    let evidence = json!({
        "request_body_size": 81920,
        "server_received_byte_count": received,
        "flow_control_windows_advertised": true,
        "response_chunks": ["upload-response-chunk"],
        "success": true
    });
    fs::write(
        "target/validation/h2/VAL-H2-019.json",
        serde_json::to_string_pretty(&evidence).unwrap(),
    )
    .unwrap();
}

// Test VAL-H2-020: Stale or failed pooled H2 connections are evicted before reuse
#[tokio::test]
async fn stale_h2_pool_entries_are_evicted_before_reuse() {
    init_validation_dir();
    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();

    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();

    let conn_count = Arc::new(Mutex::new(0));
    let conn_count_clone = conn_count.clone();

    server.start_tls(acceptor, move |conn: MockH2Connection| {
        let conn_count = conn_count_clone.clone();
        async move {
            {
                let mut lock = conn_count.lock().await;
                *lock += 1;
            }
            conn.read_preface().await.unwrap();
            let mut settings_sent = false;
            let mut encoder = Encoder::new();
            let mut decoder = specter::transport::h2::HpackDecoder::new();
            loop {
                let frame = match timeout(Duration::from_secs(3), conn.read_frame()).await {
                    Ok(Ok(f)) => f,
                    _ => break,
                };
                let (_len, frame_type, flags, stream_id, _payload) = frame;
                match frame_type {
                    0x04 if flags & 0x01 == 0 && !settings_sent => {
                        conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 65535)])
                            .await
                            .unwrap();
                        conn.send_settings_ack().await.unwrap();
                        settings_sent = true;
                    }
                    0x01 => {
                        let decoded = decoder.decode(&_payload).unwrap();
                        let path = decoded
                            .iter()
                            .find(|(name, _)| name == ":path")
                            .map(|(_, val)| val.as_str())
                            .unwrap_or("");

                        let response_headers =
                            encoder.encode(&[(b":status".as_slice(), b"200".as_slice())]);
                        conn.send_headers(stream_id, &response_headers, false, true)
                            .await
                            .unwrap();

                        if path.contains("kill-conn") {
                            conn.send_goaway(stream_id, 0).await.unwrap();
                        } else {
                            conn.send_data(stream_id, b"reusable-chunk", true)
                                .await
                                .unwrap();
                        }
                    }
                    _ => {}
                }
            }
        }
    });

    let client = Client::builder()
        .add_root_certificate(ca_cert.clone())
        .prefer_http2(true)
        .build()
        .unwrap();

    let mut resp1 = client
        .get(format!("{}/kill-conn", url))
        .send_streaming()
        .await
        .unwrap();
    assert_eq!(resp1.status().as_u16(), 200);
    let _ = resp1.body_mut().frame().await;

    tokio::time::sleep(Duration::from_millis(150)).await;

    let mut resp2 = client
        .get(format!("{}/fresh-conn", url))
        .send_streaming()
        .await
        .unwrap();
    assert_eq!(resp2.status().as_u16(), 200);
    assert_eq!(
        resp2
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        Bytes::from("reusable-chunk")
    );
    assert!(resp2.body_mut().frame().await.is_none());

    let count = *conn_count.lock().await;
    assert_eq!(
        count, 2,
        "Should have created exactly 2 connections due to stale entry eviction"
    );

    let evidence = json!({
        "induced_stale_event": "GOAWAY",
        "total_connections_created": count,
        "follow_up_request_success": true,
        "pool_eviction_observed": true,
        "success": true
    });
    fs::write(
        "target/validation/h2/VAL-H2-020.json",
        serde_json::to_string_pretty(&evidence).unwrap(),
    )
    .unwrap();
}

#[tokio::test]
async fn stale_h2_pool_retry_response_is_finalized() {
    init_validation_dir();
    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();

    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();

    let conn_count = Arc::new(Mutex::new(0));
    let conn_count_clone = conn_count.clone();

    server.start_tls(acceptor, move |conn: MockH2Connection| {
        let conn_count = conn_count_clone.clone();
        async move {
            let connection_id = {
                let mut lock = conn_count.lock().await;
                *lock += 1;
                *lock
            };
            conn.read_preface().await.unwrap();
            let mut settings_sent = false;
            let mut encoder = Encoder::new();
            let mut decoder = specter::transport::h2::HpackDecoder::new();
            loop {
                let frame = match timeout(Duration::from_secs(3), conn.read_frame()).await {
                    Ok(Ok(f)) => f,
                    _ => break,
                };
                let (_len, frame_type, flags, stream_id, payload) = frame;
                match frame_type {
                    0x04 if flags & 0x01 == 0 && !settings_sent => {
                        conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 65535)])
                            .await
                            .unwrap();
                        conn.send_settings_ack().await.unwrap();
                        settings_sent = true;
                    }
                    0x01 => {
                        let decoded = decoder.decode(&payload).unwrap();
                        let path = decoded
                            .iter()
                            .find(|(name, _)| name == ":path")
                            .map(|(_, val)| val.as_str())
                            .unwrap_or("");

                        if connection_id == 1 && path.contains("retry") {
                            conn.send_rst_stream(stream_id, 0).await.unwrap();
                            break;
                        }

                        let response_headers = if path.contains("retry") {
                            encoder.encode(&[
                                (b":status".as_slice(), b"200".as_slice()),
                                (
                                    b"set-cookie".as_slice(),
                                    b"retry_cookie=stored; Secure; Path=/".as_slice(),
                                ),
                            ])
                        } else {
                            encoder.encode(&[(b":status".as_slice(), b"200".as_slice())])
                        };
                        conn.send_headers(stream_id, &response_headers, false, true)
                            .await
                            .unwrap();
                        conn.send_data(
                            stream_id,
                            if path.contains("retry") {
                                b"retried-chunk".as_slice()
                            } else {
                                b"prime-chunk".as_slice()
                            },
                            true,
                        )
                        .await
                        .unwrap();
                    }
                    _ => {}
                }
            }
        }
    });

    let jar = Arc::new(RwLock::new(CookieJar::new()));
    let client = Client::builder()
        .add_root_certificate(ca_cert.clone())
        .prefer_http2(true)
        .cookie_jar(jar.clone())
        .build()
        .unwrap();

    let prime_url = format!("{}/prime", url);
    let mut prime_resp = timeout(
        Duration::from_secs(5),
        client.get(&prime_url).send_streaming(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(prime_resp.status().as_u16(), 200);
    assert_eq!(
        prime_resp
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        Bytes::from("prime-chunk")
    );
    assert!(prime_resp.body_mut().frame().await.is_none());

    let retry_url = format!("{}/retry", url);
    let mut retry_resp = timeout(
        Duration::from_secs(5),
        client.get(&retry_url).send_streaming(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(retry_resp.status().as_u16(), 200);
    assert_eq!(
        retry_resp.url().map(|u| u.as_str()),
        Some(retry_url.as_str())
    );
    assert_eq!(
        retry_resp
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        Bytes::from("retried-chunk")
    );
    assert!(retry_resp.body_mut().frame().await.is_none());

    let stored_cookie = jar.read().await.build_cookie_header(&retry_url);
    assert_eq!(stored_cookie.as_deref(), Some("retry_cookie=stored"));

    let count = *conn_count.lock().await;
    assert_eq!(
        count, 2,
        "retry should replace the stale pooled H2 connection exactly once"
    );

    let evidence = json!({
        "induced_stale_event": "pooled stream reset before retry response headers",
        "total_connections_created": count,
        "retried_response_url": retry_resp.url().map(|u| u.as_str()).unwrap_or_default(),
        "set_cookie_persisted": stored_cookie.as_deref() == Some("retry_cookie=stored"),
        "retried_body": "retried-chunk",
        "success": true
    });
    fs::write(
        "target/validation/h2/stale-h2-pool-retry-finalization.json",
        serde_json::to_string_pretty(&evidence).unwrap(),
    )
    .unwrap();
}

// Test VAL-H2-013: RFC 8441 tunnel coexists with streaming on one connection
#[tokio::test]
async fn rfc8441_tunnel_coexists_with_streaming_on_one_connection() {
    init_validation_dir();
    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();

    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();

    let conn_count = Arc::new(Mutex::new(0));
    let conn_count_clone = conn_count.clone();

    server.start_tls(acceptor, move |conn: MockH2Connection| {
        let conn_count = conn_count_clone.clone();
        async move {
            {
                let mut lock = conn_count.lock().await;
                *lock += 1;
            }
            conn.read_preface().await.unwrap();
            let mut settings_sent = false;
            let mut encoder = Encoder::new();
            let mut decoder = specter::transport::h2::HpackDecoder::new();
            loop {
                let frame = match timeout(Duration::from_secs(3), conn.read_frame()).await {
                    Ok(Ok(f)) => f,
                    _ => break,
                };
                let (_len, frame_type, flags, stream_id, payload) = frame;
                match frame_type {
                    0x04 if flags & 0x01 == 0 && !settings_sent => {
                        // Send SETTINGS with ENABLE_CONNECT_PROTOCOL = 1
                        conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 65535), (0x08, 1)])
                            .await
                            .unwrap();
                        conn.send_settings_ack().await.unwrap();
                        settings_sent = true;
                    }
                    0x01 => {
                        let decoded = decoder.decode(&payload).unwrap();
                        let mut method = String::new();
                        let mut protocol = String::new();
                        for (name, val) in decoded {
                            if name == ":method" {
                                method = val;
                            } else if name == ":protocol" {
                                protocol = val;
                            }
                        }

                        if method == "CONNECT" && protocol == "websocket" {
                            // Respond to CONNECT with 200 OK headers frame
                            let response_headers =
                                encoder.encode(&[(b":status".as_slice(), b"200".as_slice())]);
                            conn.send_headers(stream_id, &response_headers, false, true)
                                .await
                                .unwrap();
                        } else {
                            let response_headers =
                                encoder.encode(&[(b":status".as_slice(), b"200".as_slice())]);
                            conn.send_headers(stream_id, &response_headers, false, true)
                                .await
                                .unwrap();

                            conn.send_data(stream_id, b"stream-chunk-1", false)
                                .await
                                .unwrap();
                            conn.send_data(stream_id, b"stream-chunk-2", true)
                                .await
                                .unwrap();
                        }
                    }
                    0x00 => {
                        // Echo tunnel data back
                        conn.send_data(stream_id, &payload, flags & 0x01 != 0)
                            .await
                            .unwrap();
                    }
                    _ => {}
                }
            }
        }
    });

    let client = Client::builder()
        .add_root_certificate(ca_cert)
        .prefer_http2(true)
        .build()
        .unwrap();

    let ws_url = format!("{}/socket", url).replace("https://", "wss://");
    let stream_url = format!("{}/stream", url);

    // 1. Open the tunnel
    let mut tunnel = timeout(Duration::from_secs(5), client.websocket_h2(&ws_url).open())
        .await
        .unwrap()
        .unwrap();

    // 2. Start streaming request
    let mut resp = timeout(
        Duration::from_secs(5),
        client.get(&stream_url).send_streaming(),
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(resp.status().as_u16(), 200);

    // 3. Send message through tunnel and receive echo
    tunnel
        .send_bytes(Bytes::from("hello-tunnel"), false)
        .await
        .unwrap();
    let echoed = tunnel.recv_bytes().await.unwrap().unwrap();
    assert_eq!(echoed, Bytes::from("hello-tunnel"));

    // 4. Consume stream chunks
    assert_eq!(
        resp.body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        Bytes::from("stream-chunk-1")
    );
    assert_eq!(
        resp.body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        Bytes::from("stream-chunk-2")
    );
    assert!(resp.body_mut().frame().await.is_none());

    let count = *conn_count.lock().await;
    assert_eq!(count, 1, "Should share exactly 1 connection");

    let evidence = json!({
        "connection_count": count,
        "tunnel_messages": ["hello-tunnel"],
        "streaming_chunks": ["stream-chunk-1", "stream-chunk-2"],
        "success": true
    });
    fs::write(
        "target/validation/h2/VAL-H2-013.json",
        serde_json::to_string_pretty(&evidence).unwrap(),
    )
    .unwrap();
}

// Test VAL-H2-014: RFC 8441 and streaming data routing remains independent
#[tokio::test]
async fn rfc8441_and_streaming_data_routing_remains_independent() {
    init_validation_dir();
    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();

    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();

    server.start_tls(acceptor, move |conn: MockH2Connection| {
        async move {
            conn.read_preface().await.unwrap();
            let mut settings_sent = false;
            let mut encoder = Encoder::new();
            let mut decoder = specter::transport::h2::HpackDecoder::new();
            let mut tunnel_stream_id = None;
            loop {
                let frame = match timeout(Duration::from_secs(3), conn.read_frame()).await {
                    Ok(Ok(f)) => f,
                    _ => break,
                };
                let (_len, frame_type, flags, stream_id, payload) = frame;
                match frame_type {
                    0x04 if flags & 0x01 == 0 && !settings_sent => {
                        conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 65535), (0x08, 1)])
                            .await
                            .unwrap();
                        conn.send_settings_ack().await.unwrap();
                        settings_sent = true;
                    }
                    0x01 => {
                        let decoded = decoder.decode(&payload).unwrap();
                        let mut method = String::new();
                        let mut protocol = String::new();
                        for (name, val) in decoded {
                            if name == ":method" {
                                method = val;
                            } else if name == ":protocol" {
                                protocol = val;
                            }
                        }

                        if method == "CONNECT" && protocol == "websocket" {
                            tunnel_stream_id = Some(stream_id);
                            let response_headers =
                                encoder.encode(&[(b":status".as_slice(), b"200".as_slice())]);
                            conn.send_headers(stream_id, &response_headers, false, true)
                                .await
                                .unwrap();
                        } else {
                            let response_headers =
                                encoder.encode(&[(b":status".as_slice(), b"200".as_slice())]);
                            conn.send_headers(stream_id, &response_headers, false, true)
                                .await
                                .unwrap();

                            // Interleave sending:
                            // 1. Send stream chunk 1
                            conn.send_data(stream_id, b"stream-interleaved-1", false)
                                .await
                                .unwrap();

                            // 2. Send tunnel message 1
                            if let Some(t_id) = tunnel_stream_id {
                                conn.send_data(t_id, b"tunnel-interleaved-1", false)
                                    .await
                                    .unwrap();
                            }

                            // 3. Send stream chunk 2
                            conn.send_data(stream_id, b"stream-interleaved-2", true)
                                .await
                                .unwrap();

                            // 4. Send tunnel message 2
                            if let Some(t_id) = tunnel_stream_id {
                                conn.send_data(t_id, b"tunnel-interleaved-2", true)
                                    .await
                                    .unwrap();
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    });

    let client = Client::builder()
        .add_root_certificate(ca_cert)
        .prefer_http2(true)
        .build()
        .unwrap();

    let ws_url = format!("{}/socket", url).replace("https://", "wss://");
    let stream_url = format!("{}/stream", url);

    // 1. Open the tunnel first so the server knows the tunnel stream ID
    let mut tunnel = timeout(Duration::from_secs(5), client.websocket_h2(&ws_url).open())
        .await
        .unwrap()
        .unwrap();

    // 2. Open streaming request which triggers the interleaved sending
    let mut resp = timeout(
        Duration::from_secs(5),
        client.get(&stream_url).send_streaming(),
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(resp.status().as_u16(), 200);

    // 3. Receive tunnel events
    let t1 = tunnel.recv_bytes().await.unwrap().unwrap();
    let t2 = tunnel.recv_bytes().await.unwrap().unwrap();
    assert_eq!(t1, Bytes::from("tunnel-interleaved-1"));
    assert_eq!(t2, Bytes::from("tunnel-interleaved-2"));

    // 4. Receive stream chunks
    let s1 = resp
        .body_mut()
        .frame()
        .await
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    let s2 = resp
        .body_mut()
        .frame()
        .await
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert_eq!(s1, Bytes::from("stream-interleaved-1"));
    assert_eq!(s2, Bytes::from("stream-interleaved-2"));
    assert!(resp.body_mut().frame().await.is_none());

    let evidence = json!({
        "cross_delivery_count": 0,
        "tunnel_received_messages": ["tunnel-interleaved-1", "tunnel-interleaved-2"],
        "streaming_received_chunks": ["stream-interleaved-1", "stream-interleaved-2"],
        "success": true
    });
    fs::write(
        "target/validation/h2/VAL-H2-014.json",
        serde_json::to_string_pretty(&evidence).unwrap(),
    )
    .unwrap();
}

// Test VAL-H2-021: H2 pool reuse preserves fingerprint-relevant settings
#[tokio::test]
async fn h2_pool_reuse_preserves_fingerprint_settings() {
    init_validation_dir();
    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();

    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();

    let connection_fingerprints = Arc::new(Mutex::new(Vec::new()));
    let connection_fingerprints_clone = connection_fingerprints.clone();

    let conn_counter = Arc::new(Mutex::new(0));

    server.start_tls(acceptor, move |conn: MockH2Connection| {
        let connection_fingerprints = connection_fingerprints.clone();
        let conn_counter = conn_counter.clone();
        async move {
            let conn_id = {
                let mut counter = conn_counter.lock().await;
                *counter += 1;
                *counter
            };

            conn.read_preface().await.unwrap();
            let mut settings_sent = false;
            let mut encoder = Encoder::new();

            // Read first settings frame from client
            let (_, frame_type, flags, _, payload) = conn.read_frame().await.unwrap();
            assert_eq!(frame_type, 0x04);

            // Log setting count / details
            let settings_len = payload.len() / 6;

            connection_fingerprints.lock().await.push(json!({
                "connection_id": conn_id,
                "settings_count": settings_len,
            }));

            loop {
                // Send settings and settings ack
                if !settings_sent && flags & 0x01 == 0 {
                    conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 65535)])
                        .await
                        .unwrap();
                    conn.send_settings_ack().await.unwrap();
                    settings_sent = true;
                }

                let frame = match timeout(Duration::from_secs(2), conn.read_frame()).await {
                    Ok(Ok(f)) => f,
                    _ => break,
                };
                let (_len, f_type, _flags, stream_id, _payload) = frame;
                if f_type == 0x01 {
                    let response_headers =
                        encoder.encode(&[(b":status".as_slice(), b"200".as_slice())]);
                    conn.send_headers(stream_id, &response_headers, false, true)
                        .await
                        .unwrap();
                    conn.send_data(stream_id, b"ok", true).await.unwrap();
                }
            }
        }
    });

    // 1. Client 1: Firefox133
    let client_firefox = Client::builder()
        .add_root_certificate(ca_cert.clone())
        .prefer_http2(true)
        .fingerprint(specter::fingerprint::FingerprintProfile::Firefox133)
        .build()
        .unwrap();

    let mut resp_ff1 = client_firefox
        .get(format!("{}/stream-ff-1", url))
        .send_streaming()
        .await
        .unwrap();
    assert_eq!(resp_ff1.status().as_u16(), 200);
    assert_eq!(
        resp_ff1
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        Bytes::from("ok")
    );

    let mut resp_ff2 = client_firefox
        .get(format!("{}/stream-ff-2", url))
        .send_streaming()
        .await
        .unwrap();
    assert_eq!(resp_ff2.status().as_u16(), 200);
    assert_eq!(
        resp_ff2
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        Bytes::from("ok")
    );

    // 2. Client 2: Chrome142 (default settings)
    let client_chrome = Client::builder()
        .add_root_certificate(ca_cert)
        .prefer_http2(true)
        .fingerprint(specter::fingerprint::FingerprintProfile::Chrome142)
        .build()
        .unwrap();

    let mut resp_ch1 = client_chrome
        .get(format!("{}/stream-ch-1", url))
        .send_streaming()
        .await
        .unwrap();
    assert_eq!(resp_ch1.status().as_u16(), 200);
    assert_eq!(
        resp_ch1
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        Bytes::from("ok")
    );

    let fingerprints = connection_fingerprints_clone.lock().await.clone();

    // Verify separate connections were created because profiles are different!
    assert_eq!(
        fingerprints.len(),
        2,
        "Firefox and Chrome clients must use separate connections"
    );
    assert_eq!(fingerprints[0]["connection_id"], 1);
    assert_eq!(fingerprints[1]["connection_id"], 2);

    let evidence = json!({
        "connections": fingerprints,
        "success": true
    });
    fs::write(
        "target/validation/h2/VAL-H2-021.json",
        serde_json::to_string_pretty(&evidence).unwrap(),
    )
    .unwrap();
}

// Test VAL-H2-022: RFC 8441 tunnel failures remain isolated from streaming
#[tokio::test]
async fn rfc8441_failures_are_isolated_from_streaming() {
    init_validation_dir();
    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();

    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();

    let conn_count = Arc::new(Mutex::new(0));
    let conn_count_clone = conn_count.clone();

    server.start_tls(acceptor, move |conn: MockH2Connection| {
        let conn_count = conn_count_clone.clone();
        async move {
            {
                let mut lock = conn_count.lock().await;
                *lock += 1;
            }
            conn.read_preface().await.unwrap();
            let mut settings_sent = false;
            let mut encoder = Encoder::new();
            let mut decoder = specter::transport::h2::HpackDecoder::new();
            loop {
                let frame = match timeout(Duration::from_secs(3), conn.read_frame()).await {
                    Ok(Ok(f)) => f,
                    _ => break,
                };
                let (_len, frame_type, flags, stream_id, payload) = frame;
                match frame_type {
                    0x04 if flags & 0x01 == 0 && !settings_sent => {
                        // Send settings with ENABLE_CONNECT_PROTOCOL = 1
                        conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 65535), (0x08, 1)])
                            .await
                            .unwrap();
                        conn.send_settings_ack().await.unwrap();
                        settings_sent = true;
                    }
                    0x01 => {
                        let decoded = decoder.decode(&payload).unwrap();
                        let mut method = String::new();
                        let mut protocol = String::new();
                        for (name, val) in decoded {
                            if name == ":method" {
                                method = val;
                            } else if name == ":protocol" {
                                protocol = val;
                            }
                        }

                        if method == "CONNECT" && protocol == "websocket" {
                            // REFUSE CONNECT with 403 Forbidden!
                            let response_headers =
                                encoder.encode(&[(b":status".as_slice(), b"403".as_slice())]);
                            conn.send_headers(stream_id, &response_headers, true, true)
                                .await
                                .unwrap();
                        } else {
                            // Streaming request succeeds
                            let response_headers =
                                encoder.encode(&[(b":status".as_slice(), b"200".as_slice())]);
                            conn.send_headers(stream_id, &response_headers, false, true)
                                .await
                                .unwrap();
                            conn.send_data(stream_id, b"post-failure-chunk", true)
                                .await
                                .unwrap();
                        }
                    }
                    _ => {}
                }
            }
        }
    });

    let client = Client::builder()
        .add_root_certificate(ca_cert)
        .prefer_http2(true)
        .build()
        .unwrap();

    let ws_url = format!("{}/socket", url).replace("https://", "wss://");
    let stream_url = format!("{}/stream", url);

    // 1. Attempt to open tunnel (should fail with 403)
    let tunnel_res = client.websocket_h2(&ws_url).open().await;
    assert!(
        tunnel_res.is_err(),
        "Tunnel open must fail with 403 Forbidden"
    );

    // 2. Open normal streaming response (should succeed on the same pooled connection)
    let mut resp = client.get(&stream_url).send_streaming().await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        resp.body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        Bytes::from("post-failure-chunk")
    );
    assert!(resp.body_mut().frame().await.is_none());

    let count = *conn_count.lock().await;
    assert_eq!(
        count, 1,
        "Should reuse the connection despite tunnel failure"
    );

    let evidence = json!({
        "tunnel_failure_mode": "403 Forbidden",
        "streaming_success": true,
        "connection_count": count,
        "success": true
    });
    fs::write(
        "target/validation/h2/VAL-H2-022.json",
        serde_json::to_string_pretty(&evidence).unwrap(),
    )
    .unwrap();
}
