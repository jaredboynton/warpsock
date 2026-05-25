use bytes::Bytes;
use specter::pool::multiplexer::{OriginFairQueue, PoolKey};
use specter::transport::h3::{H3Backend, H3Client};
use specter::{FingerprintProfile, PseudoHeaderOrder, RequestBody};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;

mod helpers;
use helpers::mock_h3_server::{MockEvent, MockH3Server};

const H3_IDLE_TIMEOUT_MS: u64 = 100;
const H3_IDLE_TIMEOUT: Duration = Duration::from_millis(H3_IDLE_TIMEOUT_MS);

#[test]
fn h3_pool_origin_fair_queue_rotates_fingerprint_variants_by_origin() {
    let alpha_chrome = PoolKey::new(
        "alpha.example".to_string(),
        443,
        true,
        FingerprintProfile::Chrome142,
        PseudoHeaderOrder::Chrome,
    );
    let alpha_firefox = PoolKey::new(
        "alpha.example".to_string(),
        443,
        true,
        FingerprintProfile::Firefox142,
        PseudoHeaderOrder::Firefox,
    );
    let beta_chrome = PoolKey::new(
        "beta.example".to_string(),
        443,
        true,
        FingerprintProfile::Chrome142,
        PseudoHeaderOrder::Chrome,
    );
    let mut queue = OriginFairQueue::default();

    queue.push(alpha_chrome.clone());
    queue.push(alpha_firefox.clone());
    queue.push(beta_chrome.clone());

    assert_eq!(queue.pop_next(), Some(alpha_chrome));
    assert_eq!(
        queue.pop_next(),
        Some(beta_chrome),
        "pool-level H3 scheduling must not drain one origin's fingerprint variants before another origin gets a turn"
    );
    assert_eq!(queue.pop_next(), Some(alpha_firefox));
    assert!(queue.is_empty());
}

#[tokio::test]
async fn h3_client_reuses_pooled_connection_for_same_authority() {
    let server = MockH3Server::new().await.unwrap();
    let connection_count = server.connection_count();
    let url = server.url();

    server.start(|conn| async move {
        for _ in 0..2 {
            let stream_id = loop {
                match conn.read_event().await {
                    Some(MockEvent::Headers { stream_id, .. }) => break stream_id,
                    Some(_) => continue,
                    None => return,
                }
            };

            conn.send_response_headers(
                stream_id,
                vec![(":status", "200"), ("content-type", "text/plain")],
                false,
            )
            .await;
            conn.send_response_data(stream_id, b"ok", true).await;
        }
    });

    let client = H3Client::new().danger_accept_invalid_certs(true);
    let first = client
        .send_request(&url, "GET", vec![], None)
        .await
        .unwrap();
    let second = client
        .send_request(&url, "GET", vec![], None)
        .await
        .unwrap();

    assert_eq!(first.status(), 200);
    assert_eq!(second.status(), 200);
    assert_eq!(
        first.buffered_bytes().unwrap_or(&Bytes::new()).as_ref(),
        b"ok"
    );
    assert_eq!(
        second.buffered_bytes().unwrap_or(&Bytes::new()).as_ref(),
        b"ok"
    );

    assert_eq!(connection_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn h3_pool_reuses_live_same_key_connection() {
    let server = MockH3Server::new().await.unwrap();
    let connection_count = server.connection_count();
    let url = server.url();

    server.start(|conn| async move {
        for _ in 0..2 {
            let stream_id = loop {
                match conn.read_event().await {
                    Some(MockEvent::Headers { stream_id, .. }) => break stream_id,
                    Some(_) => continue,
                    None => return,
                }
            };

            conn.send_response_headers(stream_id, vec![(":status", "200")], false)
                .await;
            conn.send_response_data(stream_id, b"chunk", true).await;
        }
    });

    let client = H3Client::new().danger_accept_invalid_certs(true);

    // First streaming request
    let mut response1 = client
        .send_streaming(&url, "GET", vec![], RequestBody::Empty)
        .await
        .unwrap();
    assert_eq!(response1.status(), 200);
    assert_eq!(
        response1
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        bytes::Bytes::from_static(b"chunk")
    );
    assert!(response1.body_mut().frame().await.is_none());

    // Second streaming request
    let mut response2 = client
        .send_streaming(&url, "GET", vec![], RequestBody::Empty)
        .await
        .unwrap();
    assert_eq!(response2.status(), 200);
    assert_eq!(
        response2
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        bytes::Bytes::from_static(b"chunk")
    );
    assert!(response2.body_mut().frame().await.is_none());

    assert_eq!(connection_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn h3_client_exposes_reusable_handle_for_streaming_requests() {
    let server = MockH3Server::new().await.unwrap();
    let connection_count = server.connection_count();
    let url = server.url();

    server.start(|conn| async move {
        for _ in 0..2 {
            let stream_id = loop {
                match conn.read_event().await {
                    Some(MockEvent::Headers { stream_id, .. }) => break stream_id,
                    Some(_) => continue,
                    None => return,
                }
            };

            conn.send_response_headers(stream_id, vec![(":status", "200")], false)
                .await;
            conn.send_response_data(stream_id, b"chunk", true).await;
        }
    });

    let client = H3Client::new().danger_accept_invalid_certs(true);
    let handle = client.handle(&url).await.unwrap();
    let uri: http::Uri = url.parse().unwrap();

    for _ in 0..2 {
        let mut response = handle
            .send_streaming(http::Method::GET, &uri, vec![], RequestBody::Empty)
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            response
                .body_mut()
                .frame()
                .await
                .unwrap()
                .unwrap()
                .into_data()
                .unwrap(),
            bytes::Bytes::from_static(b"chunk")
        );
        assert!(response.body_mut().frame().await.is_none());
    }

    assert_eq!(connection_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn native_h3_backend_streams_response_chunks_incrementally() {
    let server = MockH3Server::new().await.unwrap();
    let url = server.url();

    server.start(|conn| async move {
        let stream_id = loop {
            match conn.read_event().await {
                Some(MockEvent::Headers { stream_id, .. }) => break stream_id,
                Some(_) => continue,
                None => return,
            }
        };

        conn.send_response_headers(stream_id, vec![(":status", "200")], false)
            .await;
        conn.send_response_data(stream_id, b"native-", false).await;
        conn.send_response_data(stream_id, b"stream", true).await;
    });

    let client = H3Client::new()
        .danger_accept_invalid_certs(true)
        .with_h3_backend(H3Backend::Native);

    let mut response = client
        .send_streaming(&url, "GET", vec![], RequestBody::Empty)
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        bytes::Bytes::from_static(b"native-")
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
        bytes::Bytes::from_static(b"stream")
    );
    assert!(response.body_mut().frame().await.is_none());
}

#[tokio::test]
async fn h3_pool_separates_authority_and_fingerprint_keys() {
    let server1 = MockH3Server::new().await.unwrap();
    let connection_count1 = server1.connection_count();
    let url1 = server1.url();

    let server2 = MockH3Server::new().await.unwrap();
    let connection_count2 = server2.connection_count();
    let url2 = server2.url();

    server1.start(|conn| async move {
        let stream_id = loop {
            match conn.read_event().await {
                Some(MockEvent::Headers { stream_id, .. }) => break stream_id,
                Some(_) => continue,
                None => return,
            }
        };
        conn.send_response_headers(stream_id, vec![(":status", "200")], false)
            .await;
        conn.send_response_data(stream_id, b"ok1", true).await;
    });

    server2.start(|conn| async move {
        let stream_id = loop {
            match conn.read_event().await {
                Some(MockEvent::Headers { stream_id, .. }) => break stream_id,
                Some(_) => continue,
                None => return,
            }
        };
        conn.send_response_headers(stream_id, vec![(":status", "200")], false)
            .await;
        conn.send_response_data(stream_id, b"ok2", true).await;
    });

    let client = H3Client::new().danger_accept_invalid_certs(true);

    let mut resp1 = client
        .send_streaming(&url1, "GET", vec![], RequestBody::Empty)
        .await
        .unwrap();
    assert_eq!(resp1.status(), 200);
    assert_eq!(
        resp1
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        bytes::Bytes::from_static(b"ok1")
    );

    let mut resp2 = client
        .send_streaming(&url2, "GET", vec![], RequestBody::Empty)
        .await
        .unwrap();
    assert_eq!(resp2.status(), 200);
    assert_eq!(
        resp2
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        bytes::Bytes::from_static(b"ok2")
    );

    assert_eq!(connection_count1.load(Ordering::SeqCst), 1);
    assert_eq!(connection_count2.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn h3_pool_concurrent_streams_are_isolated() {
    let server = MockH3Server::new().await.unwrap();
    let connection_count = server.connection_count();
    let url = server.url();

    server.start(|conn| async move {
        for _ in 0..8 {
            let (stream_id, headers) = loop {
                match conn.read_event().await {
                    Some(MockEvent::Headers { stream_id, headers }) => break (stream_id, headers),
                    Some(_) => continue,
                    None => return,
                }
            };
            let path = headers
                .iter()
                .find(|(name, _)| name == ":path")
                .map(|(_, value)| value.clone())
                .unwrap_or_else(|| "/stream/unknown".to_string());
            let marker = path.rsplit('/').next().unwrap_or("unknown").to_string();

            conn.send_response_headers(stream_id, vec![(":status", "200")], false)
                .await;
            conn.send_response_data(stream_id, format!("{marker}-a").as_bytes(), false)
                .await;
            conn.send_response_data(stream_id, format!("{marker}-b").as_bytes(), true)
                .await;
        }
    });

    let client = H3Client::new().danger_accept_invalid_certs(true);
    let mut tasks = Vec::new();

    for idx in 0..8 {
        let client = client.clone();
        let req_url = format!("{url}/stream/{idx}");
        tasks.push(tokio::spawn(async move {
            let mut response = client
                .send_streaming(&req_url, "GET", vec![], RequestBody::Empty)
                .await
                .unwrap();
            assert_eq!(response.status(), 200);

            let mut chunks = Vec::new();
            while let Some(chunk) = response.body_mut().frame().await {
                chunks
                    .push(String::from_utf8(chunk.unwrap().into_data().unwrap().to_vec()).unwrap());
            }
            (idx, chunks)
        }));
    }

    for task in tasks {
        let (idx, chunks) = task.await.unwrap();
        assert_eq!(
            chunks,
            vec![format!("{idx}-a"), format!("{idx}-b")],
            "stream {idx} received wrong chunks"
        );
    }

    assert_eq!(connection_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn h3_pool_reconnects_after_idle_timeout() {
    let server = MockH3Server::new().await.unwrap();
    let connection_count = server.connection_count();
    let url = server.url();

    server.start(|conn| async move {
        for _ in 0..2 {
            let stream_id = loop {
                match conn.read_event().await {
                    Some(MockEvent::Headers { stream_id, .. }) => break stream_id,
                    Some(_) => continue,
                    None => return,
                }
            };
            conn.send_response_headers(stream_id, vec![(":status", "200")], false)
                .await;
            conn.send_response_data(stream_id, b"chunk", true).await;
        }
    });

    let client = H3Client::new()
        .danger_accept_invalid_certs(true)
        .with_max_idle_timeout(H3_IDLE_TIMEOUT_MS);

    let mut response1 = client
        .send_streaming(&url, "GET", vec![], RequestBody::Empty)
        .await
        .unwrap();
    assert_eq!(response1.status(), 200);
    assert_eq!(
        response1
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        bytes::Bytes::from_static(b"chunk")
    );

    assert!(response1.body_mut().frame().await.is_none());

    tokio::time::sleep_until(tokio::time::Instant::now() + H3_IDLE_TIMEOUT * 2).await;

    let mut response2 = client
        .send_streaming(&url, "GET", vec![], RequestBody::Empty)
        .await
        .unwrap();
    assert_eq!(response2.status(), 200);
    assert_eq!(
        response2
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        bytes::Bytes::from_static(b"chunk")
    );

    assert_eq!(connection_count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn h3_pool_evicts_closed_or_draining_connections() {
    let server = MockH3Server::new().await.unwrap();
    let connection_count = server.connection_count();
    let url = server.url();
    let first_stream_drained = Arc::new(Notify::new());

    let connection_count_clone = connection_count.clone();
    let first_stream_drained_for_server = first_stream_drained.clone();
    server.start(move |conn| {
        let connection_count = connection_count_clone.clone();
        let first_stream_drained = first_stream_drained_for_server.clone();
        async move {
            let is_first = connection_count.load(Ordering::SeqCst) <= 1;

            if is_first {
                // First stream: respond and then send GoAway
                let stream_id1 = loop {
                    match conn.read_event().await {
                        Some(MockEvent::Headers { stream_id, .. }) => break stream_id,
                        Some(_) => continue,
                        None => return,
                    }
                };
                conn.send_response_headers(stream_id1, vec![(":status", "200")], false)
                    .await;
                conn.send_response_data(stream_id1, b"first", true).await;

                tokio::time::timeout(Duration::from_secs(1), first_stream_drained.notified())
                    .await
                    .expect("client should drain first stream before GOAWAY");
                conn.send_goaway(8).await; // Stream IDs lower than 8 are ok, higher are rejected/GOAWAY
            } else {
                // Second stream (on the new connection)
                let stream_id2 = loop {
                    match conn.read_event().await {
                        Some(MockEvent::Headers { stream_id, .. }) => break stream_id,
                        Some(_) => continue,
                        None => return,
                    }
                };
                conn.send_response_headers(stream_id2, vec![(":status", "200")], false)
                    .await;
                conn.send_response_data(stream_id2, b"second", true).await;
            }
        }
    });

    let client = H3Client::new().danger_accept_invalid_certs(true);
    let first_handle = client.handle(&url).await.unwrap();

    let mut resp1 = client
        .send_streaming(&url, "GET", vec![], RequestBody::Empty)
        .await
        .unwrap();
    assert_eq!(resp1.status(), 200);
    assert_eq!(
        resp1
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        bytes::Bytes::from_static(b"first")
    );
    assert!(resp1.body_mut().frame().await.is_none());
    first_stream_drained.notify_one();

    tokio::time::timeout(Duration::from_secs(1), async {
        while !first_handle.is_draining() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("first H3 handle should observe GOAWAY and enter draining");

    let mut resp2 = tokio::time::timeout(
        Duration::from_secs(1),
        client.send_streaming(&url, "GET", vec![], RequestBody::Empty),
    )
    .await
    .expect("second request should open a fresh H3 connection")
    .unwrap();
    assert_eq!(resp2.status(), 200);
    assert_eq!(
        resp2
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        bytes::Bytes::from_static(b"second")
    );

    assert_eq!(connection_count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn native_h3_pool_evicts_draining_connection_after_goaway() {
    let server = MockH3Server::new().await.unwrap();
    let connection_count = server.connection_count();
    let url = server.url();
    let first_stream_drained = Arc::new(Notify::new());

    let connection_count_clone = connection_count.clone();
    let first_stream_drained_for_server = first_stream_drained.clone();
    server.start(move |conn| {
        let connection_count = connection_count_clone.clone();
        let first_stream_drained = first_stream_drained_for_server.clone();
        async move {
            let is_first = connection_count.load(Ordering::SeqCst) <= 1;

            if is_first {
                let stream_id1 = loop {
                    match conn.read_event().await {
                        Some(MockEvent::Headers { stream_id, .. }) => break stream_id,
                        Some(_) => continue,
                        None => return,
                    }
                };
                conn.send_response_headers(stream_id1, vec![(":status", "200")], false)
                    .await;
                conn.send_response_data(stream_id1, b"first", true).await;

                tokio::time::timeout(Duration::from_secs(1), first_stream_drained.notified())
                    .await
                    .expect("client should drain first native stream before GOAWAY");
                conn.send_goaway(8).await;
            } else {
                let stream_id2 = loop {
                    match conn.read_event().await {
                        Some(MockEvent::Headers { stream_id, .. }) => break stream_id,
                        Some(_) => continue,
                        None => return,
                    }
                };
                conn.send_response_headers(stream_id2, vec![(":status", "200")], false)
                    .await;
                conn.send_response_data(stream_id2, b"second", true).await;
            }
        }
    });

    let client = H3Client::new()
        .danger_accept_invalid_certs(true)
        .with_h3_backend(H3Backend::Native);
    let first_handle = client.handle(&url).await.unwrap();

    let mut resp1 = client
        .send_streaming(&url, "GET", vec![], RequestBody::Empty)
        .await
        .unwrap();
    assert_eq!(resp1.status(), 200);
    assert_eq!(
        resp1
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        bytes::Bytes::from_static(b"first")
    );
    assert!(resp1.body_mut().frame().await.is_none());
    first_stream_drained.notify_one();

    tokio::time::timeout(Duration::from_secs(1), async {
        while !first_handle.is_draining() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("first native H3 handle should observe GOAWAY and enter draining");

    let mut resp2 = tokio::time::timeout(
        Duration::from_secs(1),
        client.send_streaming(&url, "GET", vec![], RequestBody::Empty),
    )
    .await
    .expect("second request should open a fresh native H3 connection")
    .unwrap();
    assert_eq!(resp2.status(), 200);
    assert_eq!(
        resp2
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        bytes::Bytes::from_static(b"second")
    );

    assert_eq!(connection_count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn native_h3_streaming_response_reset_wakes_body_with_error() {
    let server = MockH3Server::new().await.unwrap();
    let url = server.url();
    let first_data_seen = Arc::new(Notify::new());

    let first_data_seen_for_server = first_data_seen.clone();
    server.start(move |conn| {
        let first_data_seen = first_data_seen_for_server.clone();
        async move {
            let stream_id = loop {
                match conn.read_event().await {
                    Some(MockEvent::Headers { stream_id, .. }) => break stream_id,
                    Some(_) => continue,
                    None => return,
                }
            };

            conn.send_response_headers(stream_id, vec![(":status", "200")], false)
                .await;
            conn.send_response_data(stream_id, b"before-reset", false)
                .await;
            tokio::time::timeout(Duration::from_secs(1), first_data_seen.notified())
                .await
                .expect("client should observe first DATA before reset");
            conn.reset_stream(stream_id, 0x010c).await;
        }
    });

    let client = H3Client::new()
        .danger_accept_invalid_certs(true)
        .with_h3_backend(H3Backend::Native);

    let mut response = client
        .send_streaming(&url, "GET", vec![], RequestBody::Empty)
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        bytes::Bytes::from_static(b"before-reset")
    );
    first_data_seen.notify_one();

    let reset = tokio::time::timeout(Duration::from_secs(1), response.body_mut().frame())
        .await
        .expect("native reset should wake the streaming body")
        .expect("reset should surface as a body frame error")
        .expect_err("reset must not be reported as a successful DATA frame");
    assert!(
        reset.to_string().contains("Stream reset: 268"),
        "unexpected reset error: {reset}"
    );
}

#[tokio::test]
async fn native_h3_dropped_response_body_sends_stream_cancel() {
    let server = MockH3Server::new().await.unwrap();
    let url = server.url();

    server.start(|conn| async move {
        let first_stream_id = loop {
            match conn.read_event().await {
                Some(MockEvent::Headers { stream_id, .. }) => break stream_id,
                Some(_) => continue,
                None => return,
            }
        };
        conn.send_response_headers(first_stream_id, vec![(":status", "200")], false)
            .await;

        let mut pending_second_stream_id = None;
        let cancel_code = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                match conn.read_event().await {
                    Some(MockEvent::Reset { stream_id, code }) if stream_id == first_stream_id => {
                        break code
                    }
                    Some(MockEvent::Headers { stream_id, .. }) => {
                        pending_second_stream_id = Some(stream_id);
                    }
                    Some(_) => continue,
                    None => panic!("mock connection closed before native cancel"),
                }
            }
        })
        .await
        .expect("dropped native response body should cancel the stream");
        assert_eq!(cancel_code, 0x010c);

        let second_stream_id = match pending_second_stream_id {
            Some(stream_id) => stream_id,
            None => loop {
                match conn.read_event().await {
                    Some(MockEvent::Headers { stream_id, .. }) => break stream_id,
                    Some(_) => continue,
                    None => return,
                }
            },
        };
        conn.send_response_headers(second_stream_id, vec![(":status", "200")], false)
            .await;
        conn.send_response_data(second_stream_id, b"after-drop", true)
            .await;
    });

    let client = H3Client::new()
        .danger_accept_invalid_certs(true)
        .with_h3_backend(H3Backend::Native);

    let response = client
        .send_streaming(&url, "GET", vec![], RequestBody::Empty)
        .await
        .unwrap();
    drop(response);

    let mut followup = tokio::time::timeout(
        Duration::from_secs(2),
        client.send_streaming(&url, "GET", vec![], RequestBody::Empty),
    )
    .await
    .expect("follow-up request should not hang after native cancel")
    .unwrap();
    assert_eq!(
        followup
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        Bytes::from_static(b"after-drop")
    );
}

#[tokio::test]
async fn native_h3_connection_close_wakes_active_streaming_body() {
    let server = MockH3Server::new().await.unwrap();
    let url = server.url();

    server.start(|conn| async move {
        let stream_id = loop {
            match conn.read_event().await {
                Some(MockEvent::Headers { stream_id, .. }) => break stream_id,
                Some(_) => continue,
                None => return,
            }
        };
        conn.send_response_headers(stream_id, vec![(":status", "200")], false)
            .await;
        conn.close_connection(true, 0x0100, b"native close").await;
    });

    let client = H3Client::new()
        .danger_accept_invalid_certs(true)
        .with_h3_backend(H3Backend::Native);

    let mut response = client
        .send_streaming(&url, "GET", vec![], RequestBody::Empty)
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let close = tokio::time::timeout(Duration::from_secs(1), response.body_mut().frame())
        .await
        .expect("native connection close should wake active body")
        .expect("connection close should surface as a body error")
        .expect_err("connection close must not be reported as successful DATA");
    let close = close.to_string();
    assert!(
        close.contains("Connection close")
            && close.contains("0x100")
            && close.contains("native close"),
        "unexpected connection close error: {close}"
    );
}
