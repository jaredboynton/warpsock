use bytes::Bytes;
use specter::transport::h3::H3Client;
use specter::{Client, Error, HttpVersion, RequestBody};
use std::sync::atomic::Ordering;
use std::time::Duration;

mod helpers;
use helpers::mock_h3_server::{MockEvent, MockH3Server};

#[tokio::test]
async fn h3_response_body_is_poll_based() {
    fn assert_http_body<T: http_body::Body<Data = Bytes, Error = Error>>(_: &T) {}

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
        conn.send_response_data(stream_id, b"poll", false).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        conn.send_response_data(stream_id, b"-body", true).await;
    });

    let client = H3Client::new().danger_accept_invalid_certs(true);
    let mut response = client
        .send_streaming(&url, "GET", vec![], RequestBody::Empty)
        .await
        .unwrap();
    assert_http_body(response.body());
    assert!(response.body().is_streaming());

    let first = response
        .body_mut()
        .frame()
        .await
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert_eq!(first, Bytes::from_static(b"poll"));
    let second = response
        .body_mut()
        .frame()
        .await
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert_eq!(second, Bytes::from_static(b"-body"));
    assert!(response.body_mut().frame().await.is_none());

    let h3_mod = std::fs::read_to_string("src/transport/h3/mod.rs").unwrap();
    let h3_handle = std::fs::read_to_string("src/transport/h3/handle.rs").unwrap();
    let h3_driver = std::fs::read_to_string("src/transport/h3/driver.rs").unwrap();
    assert!(
        !h3_mod.contains("mpsc::Receiver<Result<Bytes>>")
            && !h3_handle.contains("mpsc::Receiver<Result<Bytes>>")
            && !h3_driver.contains("streaming_body_tx")
    );
}

#[tokio::test]
async fn h3_response_body_delivers_error_after_buffered_data() {
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
        conn.send_response_data(stream_id, b"before-reset", false)
            .await;
        conn.reset_stream(stream_id, 0x010c).await;
    });

    let client = H3Client::new().danger_accept_invalid_certs(true);
    let mut response = client
        .send_streaming(&url, "GET", vec![], RequestBody::Empty)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(25)).await;

    let first = response
        .body_mut()
        .frame()
        .await
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert_eq!(first, Bytes::from_static(b"before-reset"));

    let second = tokio::time::timeout(Duration::from_secs(1), response.body_mut().frame())
        .await
        .expect("reset after buffered DATA must not hang")
        .unwrap();
    assert!(matches!(second, Err(Error::Quic(_))));
}

#[tokio::test]
async fn h3_dropped_response_body_cancels_stream() {
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

        let second_stream_id = loop {
            match conn.read_event().await {
                Some(MockEvent::Headers { stream_id, .. }) => break stream_id,
                Some(_) => continue,
                None => return,
            }
        };
        conn.send_response_headers(second_stream_id, vec![(":status", "200")], false)
            .await;
        conn.send_response_data(second_stream_id, b"after-drop", true)
            .await;
    });

    let client = H3Client::new().danger_accept_invalid_certs(true);
    let response = client
        .send_streaming(&url, "GET", vec![], RequestBody::Empty)
        .await
        .unwrap();
    drop(response);

    let mut followup = client
        .send_streaming(&url, "GET", vec![], RequestBody::Empty)
        .await
        .unwrap();
    let body = followup
        .body_mut()
        .frame()
        .await
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert_eq!(body, Bytes::from_static(b"after-drop"));
}

#[tokio::test]
async fn h3_streaming_returns_headers_before_body_completion() {
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
        tokio::time::sleep(Duration::from_millis(100)).await;
        conn.send_response_data(stream_id, b"one", false).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        conn.send_response_data(stream_id, b"two", true).await;
    });

    let client = H3Client::new().danger_accept_invalid_certs(true);
    let mut response = tokio::time::timeout(
        Duration::from_secs(3),
        client.send_streaming(&url, "GET", vec![], RequestBody::Empty),
    )
    .await
    .expect("headers should arrive before body finishes")
    .unwrap();

    assert_eq!(response.status(), 200);
    assert!(response.body().is_streaming());

    let first = response
        .body_mut()
        .frame()
        .await
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert_eq!(first, Bytes::from_static(b"one"));
    let second = response
        .body_mut()
        .frame()
        .await
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert_eq!(second, Bytes::from_static(b"two"));
    assert!(response.body_mut().frame().await.is_none());
}

#[tokio::test]
async fn h3_streaming_delivers_incremental_ordered_data() {
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
        conn.send_response_data(stream_id, b"chunk-a", false).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        conn.send_response_data(stream_id, b"chunk-b", false).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        conn.send_response_data(stream_id, b"chunk-c", true).await;
    });

    let client = H3Client::new().danger_accept_invalid_certs(true);
    let mut response = client
        .send_streaming(&url, "GET", vec![], RequestBody::Empty)
        .await
        .unwrap();

    let first = tokio::time::timeout(Duration::from_millis(150), response.body_mut().frame())
        .await
        .expect("first DATA must arrive before FIN")
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert_eq!(first, Bytes::from_static(b"chunk-a"));

    let second = response
        .body_mut()
        .frame()
        .await
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    let third = response
        .body_mut()
        .frame()
        .await
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert_eq!(second, Bytes::from_static(b"chunk-b"));
    assert_eq!(third, Bytes::from_static(b"chunk-c"));
    assert!(response.body_mut().frame().await.is_none());
}

#[tokio::test]
async fn h3_streaming_handles_benchmark_sized_chunks() {
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
        for idx in 0..5 {
            let marker = b'a' + idx;
            let chunk = vec![marker; 16 * 1024];
            conn.send_response_data(stream_id, &chunk, idx == 4).await;
        }
    });

    let client = H3Client::new().danger_accept_invalid_certs(true);
    let mut response = client
        .send_streaming(&url, "GET", vec![], RequestBody::Empty)
        .await
        .unwrap();

    let mut body = Vec::new();
    while let Some(frame) = response.body_mut().frame().await {
        body.extend_from_slice(&frame.unwrap().into_data().unwrap());
    }

    assert_eq!(body.len(), 5 * 16 * 1024);
    for idx in 0..5 {
        let marker = b'a' + idx as u8;
        let start = idx * 16 * 1024;
        let end = start + 16 * 1024;
        assert!(body[start..end].iter().all(|byte| *byte == marker));
    }
}

#[tokio::test]
async fn h3_streaming_fin_clean_eof_and_reuse() {
    let server = MockH3Server::new().await.unwrap();
    let connection_count = server.connection_count();
    let url = server.url();

    server.start(|conn| async move {
        for body in [b"first".as_slice(), b"second".as_slice()] {
            let stream_id = loop {
                match conn.read_event().await {
                    Some(MockEvent::Headers { stream_id, .. }) => break stream_id,
                    Some(_) => continue,
                    None => return,
                }
            };

            conn.send_response_headers(stream_id, vec![(":status", "200")], false)
                .await;
            conn.send_response_data(stream_id, body, true).await;
        }
    });

    let client = H3Client::new().danger_accept_invalid_certs(true);
    let mut first_response = client
        .send_streaming(&url, "GET", vec![], RequestBody::Empty)
        .await
        .unwrap();
    assert_eq!(
        first_response
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        Bytes::from_static(b"first")
    );
    assert!(first_response.body_mut().frame().await.is_none());
    assert!(first_response.body_mut().frame().await.is_none());

    let mut second_response = client
        .send_streaming(&url, "GET", vec![], RequestBody::Empty)
        .await
        .unwrap();
    assert_eq!(
        second_response
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        Bytes::from_static(b"second")
    );
    assert!(second_response.body_mut().frame().await.is_none());

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(connection_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn h3_streaming_reset_and_error_propagation() {
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
        conn.reset_stream(stream_id, 0x010c).await;
    });

    let client = H3Client::new().danger_accept_invalid_certs(true);
    let mut response = client
        .send_streaming(&url, "GET", vec![], RequestBody::Empty)
        .await
        .unwrap();

    let err = tokio::time::timeout(Duration::from_secs(2), response.body_mut().frame())
        .await
        .expect("reset must be reported promptly")
        .expect("reset must produce a body item")
        .expect_err("reset must not become clean EOF");
    assert!(err.to_string().contains("reset"));
}

#[tokio::test]
async fn h3_streaming_supports_request_bodies() {
    let server = MockH3Server::new().await.unwrap();
    let url = server.url();

    server.start(|conn| async move {
        let mut stream_id = None;
        let mut received = Vec::new();
        loop {
            match conn.read_event().await {
                Some(MockEvent::Headers { stream_id: id, .. }) => stream_id = Some(id),
                Some(MockEvent::Data { data, .. }) => received.extend_from_slice(&data),
                Some(MockEvent::Finished { stream_id: id }) => {
                    assert_eq!(stream_id, Some(id));
                    assert_eq!(received, b"upload-body");
                    conn.send_response_headers(id, vec![(":status", "200")], false)
                        .await;
                    conn.send_response_data(id, b"accepted", true).await;
                    return;
                }
                Some(_) => {}
                None => return,
            }
        }
    });

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let mut response = client
        .post(&url)
        .version(HttpVersion::Http3Only)
        .body("upload-body")
        .send_streaming()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    let chunk = response
        .body_mut()
        .frame()
        .await
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert_eq!(chunk, Bytes::from_static(b"accepted"));
    assert!(response.body_mut().frame().await.is_none());
}

#[tokio::test]
async fn h3_streaming_does_not_duplicate_partial_non_idempotent_requests() {
    let server = MockH3Server::new().await.unwrap();
    let connection_count = server.connection_count();
    let url = server.url();

    server.start(|conn| async move {
        // First request is a POST (non-idempotent)
        let _stream_id = loop {
            match conn.read_event().await {
                Some(MockEvent::Headers { stream_id, .. }) => break stream_id,
                Some(_) => continue,
                None => return,
            }
        };

        // We close the connection (or drop it) to simulate a failure after request progressed
        // (we won't respond to the stream, simulating a failure)
    });

    let client = H3Client::new().danger_accept_invalid_certs(true);
    let res = client
        .send_streaming(
            &url,
            "POST",
            vec![],
            RequestBody::Bytes(Bytes::from_static(b"some body")),
        )
        .await;

    // It should fail and NOT retry (which means connection count should be 1, and we should get an error)
    assert!(res.is_err());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(connection_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn h3_streaming_preserves_timeouts_and_cookies() {
    let server = MockH3Server::new().await.unwrap();
    let url = server.url();

    server.start(|conn| async move {
        for _ in 0..3 {
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
                .map(|(_, value)| value.as_str())
                .unwrap_or("/");

            match path {
                "/set" => {
                    conn.send_response_headers(
                        stream_id,
                        vec![(":status", "200"), ("set-cookie", "h3cookie=ok; Path=/")],
                        false,
                    )
                    .await;
                    conn.send_response_data(stream_id, b"stored", true).await;
                }
                "/echo" => {
                    let cookie = headers
                        .iter()
                        .find(|(name, _)| name.eq_ignore_ascii_case("cookie"))
                        .map(|(_, value)| value.clone())
                        .unwrap_or_default();
                    assert!(cookie.contains("h3cookie=ok"), "missing cookie: {cookie}");
                    conn.send_response_headers(stream_id, vec![(":status", "200")], false)
                        .await;
                    conn.send_response_data(stream_id, b"cookie-ok", true).await;
                }
                "/timeout" => {
                    conn.send_response_headers(stream_id, vec![(":status", "200")], false)
                        .await;
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
                other => panic!("unexpected path {other}"),
            }
        }
    });

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .cookie_store(true)
        .read_timeout(Duration::from_millis(75))
        .build()
        .unwrap();

    let mut set_response = client
        .get(format!("{url}/set"))
        .version(HttpVersion::Http3Only)
        .send_streaming()
        .await
        .unwrap();
    assert_eq!(set_response.status(), 200);
    let chunk = set_response
        .body_mut()
        .frame()
        .await
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert_eq!(chunk, Bytes::from_static(b"stored"));
    assert!(set_response.body_mut().frame().await.is_none());

    let mut echo_response = client
        .get(format!("{url}/echo"))
        .version(HttpVersion::Http3Only)
        .send_streaming()
        .await
        .unwrap();
    assert_eq!(echo_response.status(), 200);
    let chunk = echo_response
        .body_mut()
        .frame()
        .await
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert_eq!(chunk, Bytes::from_static(b"cookie-ok"));
    assert!(echo_response.body_mut().frame().await.is_none());

    let mut timeout_response = client
        .get(format!("{url}/timeout"))
        .version(HttpVersion::Http3Only)
        .send_streaming()
        .await
        .unwrap();
    assert_eq!(timeout_response.status(), 200);
    let timeout_err =
        tokio::time::timeout(Duration::from_secs(1), timeout_response.body_mut().frame())
            .await
            .expect("read timeout should be bounded")
            .expect("read timeout should yield an error")
            .expect_err("read timeout should not be clean EOF");
    assert!(matches!(timeout_err, Error::ReadIdleTimeout(_)));
}

#[tokio::test]
async fn h3_flow_control_and_slow_consumers_do_not_starve_siblings() {
    let server = MockH3Server::new().await.unwrap();
    let url = server.url();

    server.start(|conn| async move {
        for _ in 0..2 {
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
                .map(|(_, value)| value.as_str())
                .unwrap_or("/");

            match path {
                "/slow" => {
                    conn.send_response_headers(stream_id, vec![(":status", "200")], false)
                        .await;
                    for idx in 0..64 {
                        let chunk = format!("slow-{idx:02}");
                        conn.send_response_data(stream_id, chunk.as_bytes(), false)
                            .await;
                    }
                }
                "/fast" => {
                    conn.send_response_headers(stream_id, vec![(":status", "200")], false)
                        .await;
                    conn.send_response_data(stream_id, b"fast-complete", true)
                        .await;
                }
                other => panic!("unexpected path {other}"),
            }
        }
    });

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let mut slow_response = client
        .get(format!("{url}/slow"))
        .version(HttpVersion::Http3Only)
        .send_streaming()
        .await
        .unwrap();

    let mut fast_response = client
        .get(format!("{url}/fast"))
        .version(HttpVersion::Http3Only)
        .send_streaming()
        .await
        .unwrap();

    let fast = tokio::time::timeout(Duration::from_secs(2), fast_response.body_mut().frame())
        .await
        .expect("fast sibling stream must not starve behind slow receiver")
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert_eq!(fast, Bytes::from_static(b"fast-complete"));
    assert!(fast_response.body_mut().frame().await.is_none());

    assert!(slow_response.body_mut().frame().await.is_some());
    drop(slow_response);
}
