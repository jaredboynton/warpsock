use bytes::Bytes;
use specter::transport::h3::H3Client;
use specter::RequestBody;
use std::sync::atomic::Ordering;
use std::time::Duration;

mod helpers;
use helpers::mock_h3_server::{MockEvent, MockH3Server};

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

    tokio::time::sleep(Duration::from_millis(100)).await;
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

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(connection_count.load(Ordering::SeqCst), 1);
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

    tokio::time::sleep(Duration::from_millis(100)).await;
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

    tokio::time::sleep(Duration::from_millis(100)).await;
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

    // Configure the client with a very short idle timeout
    let client = H3Client::new()
        .danger_accept_invalid_certs(true)
        .with_max_idle_timeout(100); // 100 milliseconds idle timeout

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

    // Wait for the idle timeout to kick in on client/server
    tokio::time::sleep(Duration::from_millis(250)).await;

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

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(connection_count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn h3_pool_evicts_closed_or_draining_connections() {
    let server = MockH3Server::new().await.unwrap();
    let connection_count = server.connection_count();
    let url = server.url();

    let connection_count_clone = connection_count.clone();
    server.start(move |conn| {
        let connection_count = connection_count_clone.clone();
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

                // Wait a tiny bit then send GOAWAY
                tokio::time::sleep(Duration::from_millis(50)).await;
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

    // Give background driver a tiny moment to process GOAWAY
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut resp2 = client
        .send_streaming(&url, "GET", vec![], RequestBody::Empty)
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
        bytes::Bytes::from_static(b"second")
    );

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(connection_count.load(Ordering::SeqCst), 2);
}
