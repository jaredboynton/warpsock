use bytes::Bytes;
use specter::transport::h3::H3Client;
use specter::{Client, Error, HttpVersion};
use std::sync::atomic::Ordering;
use std::time::Duration;

mod helpers;
use helpers::mock_h3_server::{MockEvent, MockH3Server};

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
    let (response, mut body_rx) = tokio::time::timeout(
        Duration::from_secs(3),
        client.send_streaming(&url, "GET", vec![], None),
    )
    .await
    .expect("headers should arrive before body finishes")
    .unwrap();

    assert_eq!(response.status(), 200);
    assert!(response.body().is_empty());

    let first = body_rx.recv().await.unwrap().unwrap();
    assert_eq!(first, Bytes::from_static(b"one"));
    let second = body_rx.recv().await.unwrap().unwrap();
    assert_eq!(second, Bytes::from_static(b"two"));
    assert!(body_rx.recv().await.is_none());
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
    let (_response, mut body_rx) = client
        .send_streaming(&url, "GET", vec![], None)
        .await
        .unwrap();

    let first = tokio::time::timeout(Duration::from_millis(150), body_rx.recv())
        .await
        .expect("first DATA must arrive before FIN")
        .unwrap()
        .unwrap();
    assert_eq!(first, Bytes::from_static(b"chunk-a"));

    let second = body_rx.recv().await.unwrap().unwrap();
    let third = body_rx.recv().await.unwrap().unwrap();
    assert_eq!(second, Bytes::from_static(b"chunk-b"));
    assert_eq!(third, Bytes::from_static(b"chunk-c"));
    assert!(body_rx.recv().await.is_none());
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
    let (_response, mut first_rx) = client
        .send_streaming(&url, "GET", vec![], None)
        .await
        .unwrap();
    assert_eq!(
        first_rx.recv().await.unwrap().unwrap(),
        Bytes::from_static(b"first")
    );
    assert!(first_rx.recv().await.is_none());
    assert!(first_rx.recv().await.is_none());

    let (_response, mut second_rx) = client
        .send_streaming(&url, "GET", vec![], None)
        .await
        .unwrap();
    assert_eq!(
        second_rx.recv().await.unwrap().unwrap(),
        Bytes::from_static(b"second")
    );
    assert!(second_rx.recv().await.is_none());

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
    let (_response, mut body_rx) = client
        .send_streaming(&url, "GET", vec![], None)
        .await
        .unwrap();

    let err = tokio::time::timeout(Duration::from_secs(2), body_rx.recv())
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
        .send_streaming(&url, "POST", vec![], Some(b"some body".to_vec()))
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
