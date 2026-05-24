//! H2 request-body streaming validation.

use bytes::Bytes;
use futures_core::Stream;
use serde_json::json;
use specter::{Client, Error};
use std::fs;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::sync::Notify;
use tokio::time::timeout;

mod helpers;
use helpers::mock_h2_server::{MockH2Connection, MockH2Server};
use helpers::tls::generate_cert_bundle;
use specter::transport::h2::hpack_impl::Encoder;

fn init_validation_dir() {
    fs::create_dir_all("target/validation/h2").unwrap();
}

fn h2_client(ca_cert: Vec<u8>) -> Client {
    Client::builder()
        .add_root_certificate(ca_cert)
        .prefer_http2(true)
        .build()
        .unwrap()
}

fn h2_acceptor() -> (boring::ssl::SslAcceptor, Vec<u8>) {
    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    (builder.build(), ca_cert)
}

async fn server_handshake(conn: &MockH2Connection) {
    conn.read_preface().await.unwrap();
    conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 65535)])
        .await
        .unwrap();
    conn.send_settings_ack().await.unwrap();
}

async fn send_ok_headers(conn: &MockH2Connection, encoder: &mut Encoder, stream_id: u32) {
    let response_headers = encoder.encode(&[(b":status".as_slice(), b"200".as_slice())]);
    conn.send_headers(stream_id, &response_headers, false, true)
        .await
        .unwrap();
}

struct CountingChunks {
    chunk: Bytes,
    remaining: usize,
    polls: Arc<AtomicUsize>,
}

impl CountingChunks {
    fn new(chunk_len: usize, chunks: usize, polls: Arc<AtomicUsize>) -> Self {
        Self {
            chunk: Bytes::from(vec![b'u'; chunk_len]),
            remaining: chunks,
            polls,
        }
    }
}

impl Stream for CountingChunks {
    type Item = std::result::Result<Bytes, Error>;

    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        if self.remaining == 0 {
            return Poll::Ready(None);
        }
        self.remaining -= 1;
        Poll::Ready(Some(Ok(self.chunk.clone())))
    }
}

#[tokio::test]
async fn h2_request_stream_flow_control_window_contention() {
    init_validation_dir();
    let (acceptor, ca_cert) = h2_acceptor();
    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();
    let first_burst_bytes = Arc::new(AtomicUsize::new(0));
    let polls_at_contention = Arc::new(AtomicUsize::new(0));
    let producer_polls = Arc::new(AtomicUsize::new(0));
    let producer_polls_server = producer_polls.clone();
    let first_burst_bytes_server = first_burst_bytes.clone();
    let polls_at_contention_server = polls_at_contention.clone();

    server.start_tls(acceptor, move |conn: MockH2Connection| {
        let first_burst_bytes = first_burst_bytes_server.clone();
        let polls_at_contention = polls_at_contention_server.clone();
        let producer_polls = producer_polls_server.clone();
        async move {
            server_handshake(&conn).await;
            let mut encoder = Encoder::new();
            let mut stream_id = 0;
            let mut total = 0usize;
            loop {
                let Ok((_, frame_type, flags, sid, payload)) =
                    timeout(Duration::from_secs(3), conn.read_frame())
                        .await
                        .unwrap()
                else {
                    break;
                };
                match frame_type {
                    0x01 => stream_id = sid,
                    0x00 => {
                        total += payload.len();
                        if total >= 65_535 && first_burst_bytes.load(Ordering::SeqCst) == 0 {
                            first_burst_bytes.store(total, Ordering::SeqCst);
                            polls_at_contention
                                .store(producer_polls.load(Ordering::SeqCst), Ordering::SeqCst);
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            conn.send_window_update(0, 1_000_000).await.unwrap();
                            conn.send_window_update(stream_id, 1_000_000).await.unwrap();
                        }
                        if flags & 0x01 != 0 {
                            send_ok_headers(&conn, &mut encoder, stream_id).await;
                            conn.send_data(stream_id, b"ok", true).await.unwrap();
                            break;
                        }
                    }
                    _ => {}
                }
            }
        }
    });

    let client = h2_client(ca_cert);
    let stream = CountingChunks::new(16_384, 16, producer_polls.clone());
    let mut response = timeout(
        Duration::from_secs(5),
        client
            .post(format!("{}/flow-control", url))
            .body_stream(stream)
            .send_streaming(),
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
        Bytes::from_static(b"ok")
    );
    assert!(first_burst_bytes.load(Ordering::SeqCst) <= 65_535 + 16_384);
    assert!(
        polls_at_contention.load(Ordering::SeqCst) < 16,
        "producer should not be eagerly drained before WINDOW_UPDATE"
    );

    fs::write(
        "target/validation/h2/VAL-H2-REQ-STREAM-001.json",
        serde_json::to_string_pretty(&json!({
            "first_burst_bytes": first_burst_bytes.load(Ordering::SeqCst),
            "polls_at_window_contention": polls_at_contention.load(Ordering::SeqCst),
            "producer_not_eagerly_drained": polls_at_contention.load(Ordering::SeqCst) < 16,
            "response_completed": true
        }))
        .unwrap(),
    )
    .unwrap();
}

#[tokio::test]
async fn h2_request_stream_10mb_under_backpressure() {
    init_validation_dir();
    let (acceptor, ca_cert) = h2_acceptor();
    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();
    let total_received = Arc::new(AtomicUsize::new(0));
    let total_received_server = total_received.clone();

    server.start_tls(acceptor, move |conn: MockH2Connection| {
        let total_received = total_received_server.clone();
        async move {
            server_handshake(&conn).await;
            let mut encoder = Encoder::new();
            let mut stream_id = 0;
            loop {
                let Ok((_, frame_type, flags, sid, payload)) =
                    timeout(Duration::from_secs(10), conn.read_frame())
                        .await
                        .unwrap()
                else {
                    break;
                };
                match frame_type {
                    0x01 => stream_id = sid,
                    0x00 => {
                        total_received.fetch_add(payload.len(), Ordering::SeqCst);
                        if !payload.is_empty() {
                            conn.send_window_update(0, payload.len() as u32)
                                .await
                                .unwrap();
                            conn.send_window_update(stream_id, payload.len() as u32)
                                .await
                                .unwrap();
                        }
                        if flags & 0x01 != 0 {
                            send_ok_headers(&conn, &mut encoder, stream_id).await;
                            conn.send_data(stream_id, b"uploaded", true).await.unwrap();
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            break;
                        }
                    }
                    _ => {}
                }
            }
        }
    });

    let client = h2_client(ca_cert);
    let polls = Arc::new(AtomicUsize::new(0));
    let stream = CountingChunks::new(64 * 1024, 160, polls);
    let mut response = timeout(
        Duration::from_secs(15),
        client
            .post(format!("{}/ten-mb", url))
            .body_stream_sized(stream, 10 * 1024 * 1024)
            .send_streaming(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(total_received.load(Ordering::SeqCst), 10 * 1024 * 1024);
    assert_eq!(
        response
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        Bytes::from_static(b"uploaded")
    );

    fs::write(
        "target/validation/h2/VAL-H2-REQ-STREAM-002.json",
        serde_json::to_string_pretty(&json!({
            "total_request_bytes": total_received.load(Ordering::SeqCst),
            "expected_request_bytes": 10 * 1024 * 1024,
            "response_completed": true
        }))
        .unwrap(),
    )
    .unwrap();
}

#[tokio::test]
async fn h2_request_stream_mid_stream_cancellation() {
    init_validation_dir();
    let (acceptor, ca_cert) = h2_acceptor();
    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();
    let rst_seen = Arc::new(AtomicBool::new(false));
    let rst_seen_server = rst_seen.clone();
    let first_data_seen = Arc::new(Notify::new());
    let first_data_seen_server = first_data_seen.clone();

    server.start_tls(acceptor, move |conn: MockH2Connection| {
        let rst_seen = rst_seen_server.clone();
        let first_data_seen = first_data_seen_server.clone();
        async move {
            server_handshake(&conn).await;
            let mut encoder = Encoder::new();
            let mut stream_id = 0;
            loop {
                let Ok((_, frame_type, _flags, sid, payload)) =
                    timeout(Duration::from_secs(5), conn.read_frame())
                        .await
                        .unwrap()
                else {
                    break;
                };
                match frame_type {
                    0x01 => stream_id = sid,
                    0x00 => {
                        first_data_seen.notify_waiters();
                        if !payload.is_empty() {
                            conn.send_window_update(0, payload.len() as u32)
                                .await
                                .unwrap();
                            conn.send_window_update(stream_id, payload.len() as u32)
                                .await
                                .unwrap();
                        }
                        send_ok_headers(&conn, &mut encoder, stream_id).await;
                        conn.send_data(stream_id, b"partial-response", false)
                            .await
                            .unwrap();
                    }
                    0x03 => {
                        rst_seen.store(true, Ordering::SeqCst);
                        break;
                    }
                    _ => {}
                }
            }
        }
    });

    let client = h2_client(ca_cert);
    let polls = Arc::new(AtomicUsize::new(0));
    let stream = CountingChunks::new(16 * 1024, 1024, polls.clone());
    let response = client
        .post(format!("{}/cancel", url))
        .body_stream(stream)
        .send_streaming()
        .await
        .unwrap();
    timeout(Duration::from_secs(2), first_data_seen.notified())
        .await
        .unwrap();
    let before_drop = polls.load(Ordering::SeqCst);
    drop(response);
    timeout(Duration::from_secs(2), async {
        loop {
            if rst_seen.load(Ordering::SeqCst) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let after_drop = polls.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        polls.load(Ordering::SeqCst),
        after_drop,
        "producer should not continue being polled after cancellation settles"
    );

    fs::write(
        "target/validation/h2/VAL-H2-REQ-STREAM-003.json",
        serde_json::to_string_pretty(&json!({
            "producer_polls_before_drop": before_drop,
            "producer_polls_after_drop": after_drop,
            "rst_stream_observed": rst_seen.load(Ordering::SeqCst),
            "producer_stopped_after_cancellation": true
        }))
        .unwrap(),
    )
    .unwrap();
}

#[tokio::test]
async fn h2_request_body_while_receiving_response_interleaves() {
    init_validation_dir();
    let (acceptor, ca_cert) = h2_acceptor();
    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();
    let upload_bytes_at_first_response = Arc::new(AtomicUsize::new(0));
    let upload_bytes_at_first_response_server = upload_bytes_at_first_response.clone();

    server.start_tls(acceptor, move |conn: MockH2Connection| {
        let upload_bytes_at_first_response = upload_bytes_at_first_response_server.clone();
        async move {
            server_handshake(&conn).await;
            let mut encoder = Encoder::new();
            let mut stream_id = 0;
            let mut uploaded = 0usize;
            let mut sent_response = false;
            loop {
                let Ok((_, frame_type, flags, sid, payload)) =
                    timeout(Duration::from_secs(5), conn.read_frame())
                        .await
                        .unwrap()
                else {
                    break;
                };
                match frame_type {
                    0x01 => stream_id = sid,
                    0x00 => {
                        uploaded += payload.len();
                        if !payload.is_empty() {
                            conn.send_window_update(0, payload.len() as u32)
                                .await
                                .unwrap();
                            conn.send_window_update(stream_id, payload.len() as u32)
                                .await
                                .unwrap();
                        }
                        if !sent_response {
                            sent_response = true;
                            upload_bytes_at_first_response.store(uploaded, Ordering::SeqCst);
                            send_ok_headers(&conn, &mut encoder, stream_id).await;
                            conn.send_data(stream_id, b"download-before-upload-end", false)
                                .await
                                .unwrap();
                        }
                        if flags & 0x01 != 0 {
                            conn.send_data(stream_id, b"-done", true).await.unwrap();
                            break;
                        }
                    }
                    _ => {}
                }
            }
        }
    });

    let client = h2_client(ca_cert);
    let polls = Arc::new(AtomicUsize::new(0));
    let stream = CountingChunks::new(16 * 1024, 4, polls);
    let mut response = timeout(
        Duration::from_secs(5),
        client
            .post(format!("{}/interleave", url))
            .body_stream(stream)
            .send_streaming(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let first = response
        .body_mut()
        .frame()
        .await
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert_eq!(first, Bytes::from_static(b"download-before-upload-end"));
    assert!(upload_bytes_at_first_response.load(Ordering::SeqCst) < 4 * 16 * 1024);

    fs::write(
        "target/validation/h2/VAL-H2-REQ-STREAM-004.json",
        serde_json::to_string_pretty(&json!({
            "upload_bytes_when_first_response_data_sent": upload_bytes_at_first_response.load(Ordering::SeqCst),
            "total_upload_bytes": 4 * 16 * 1024,
            "response_chunks_observed_before_upload_end": ["download-before-upload-end"],
            "interleaved": true
        }))
        .unwrap(),
    )
    .unwrap();
}
