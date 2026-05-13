use std::time::Duration;

use specter::{Client, CloseCode, CloseFrame};

#[path = "helpers/mock_ws_server.rs"]
mod mock_ws_server;

use mock_ws_server::{AcceptMode, MockWsServer, WsResponse};

#[tokio::test]
async fn invalid_accept_returns_handshake_error_without_close_frame() {
    let server = MockWsServer::new().await.unwrap();
    let url = server.ws_url("/invalid-accept");
    let handle = server.start_once(WsResponse {
        accept: AcceptMode::Wrong,
        ..WsResponse::default()
    });

    let err = Client::new()
        .unwrap()
        .websocket(url)
        .connect()
        .await
        .expect_err("invalid accept must fail");

    assert_error_mentions(&err, &["InvalidAccept", "Sec-WebSocket-Accept"]);
    assert!(
        handle.await.unwrap().client_frame.is_none(),
        "handshake failures must not send websocket close frames"
    );
}

#[tokio::test]
async fn extension_response_returns_unexpected_extension_without_close_frame() {
    let server = MockWsServer::new().await.unwrap();
    let url = server.ws_url("/unexpected-extension");
    let handle = server.start_once(WsResponse {
        headers: vec![(
            "Sec-WebSocket-Extensions".to_string(),
            "permessage-deflate".to_string(),
        )],
        ..WsResponse::default()
    });

    let err = Client::new()
        .unwrap()
        .websocket(url)
        .connect()
        .await
        .expect_err("unexpected extension must fail");

    assert_error_mentions(&err, &["UnexpectedExtension", "Sec-WebSocket-Extensions"]);
    assert!(
        handle.await.unwrap().client_frame.is_none(),
        "handshake failures must not send websocket close frames"
    );
}

#[tokio::test]
async fn unoffered_subprotocol_returns_unexpected_subprotocol_without_close_frame() {
    let server = MockWsServer::new().await.unwrap();
    let url = server.ws_url("/unexpected-subprotocol");
    let handle = server.start_once(WsResponse {
        headers: vec![(
            "Sec-WebSocket-Protocol".to_string(),
            "superchat".to_string(),
        )],
        ..WsResponse::default()
    });

    let err = Client::new()
        .unwrap()
        .websocket(url)
        .connect()
        .await
        .expect_err("unexpected subprotocol must fail");

    assert_error_mentions(&err, &["UnexpectedSubprotocol", "Sec-WebSocket-Protocol"]);
    assert!(
        handle.await.unwrap().client_frame.is_none(),
        "handshake failures must not send websocket close frames"
    );
}

#[tokio::test]
async fn invalid_outbound_close_codes_are_rejected_without_sending_frame() {
    for code in [
        CloseCode::Status,
        CloseCode::Abnormal,
        CloseCode::Tls,
        CloseCode::Library(1004),
        CloseCode::Library(1016),
        CloseCode::Library(2999),
    ] {
        let server = MockWsServer::new().await.unwrap();
        let url = server.ws_url("/invalid-close-code");
        let handle = server.start_once(WsResponse::default());

        let mut ws = Client::new()
            .unwrap()
            .websocket(url)
            .connect()
            .await
            .expect("websocket handshake should succeed");

        let err = ws
            .close(Some(CloseFrame {
                code,
                reason: String::new(),
            }))
            .await
            .expect_err("invalid close code must fail before sending");

        assert_error_mentions(&err, &["close code", "must not be sent"]);
        assert!(
            handle.await.unwrap().client_frame.is_none(),
            "invalid outbound close code must not write a close frame"
        );
    }
}

#[tokio::test]
async fn established_read_timeout_returns_timeout_error() {
    let server = MockWsServer::new().await.unwrap();
    let url = server.ws_url("/read-timeout");
    let handle = server.start_once(WsResponse::default());

    let mut ws = Client::new()
        .unwrap()
        .websocket(url)
        .read_timeout(Duration::from_millis(20))
        .connect()
        .await
        .expect("websocket handshake should succeed");

    let err = ws.next().await.expect_err("read timeout must fail");
    assert_error_mentions(&err, &["Timeout", "read"]);

    let _ = handle.await.unwrap();
}

fn assert_error_mentions<E: std::fmt::Debug + std::fmt::Display>(err: &E, needles: &[&str]) {
    let rendered = format!("{err:?}\n{err}");
    assert!(
        needles.iter().any(|needle| rendered.contains(needle)),
        "error did not mention any of {needles:?}: {rendered}"
    );
}
