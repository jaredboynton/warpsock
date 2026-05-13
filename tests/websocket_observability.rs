use specter::Client;

#[path = "helpers/mock_ws_server.rs"]
mod mock_ws_server;

use mock_ws_server::{AcceptMode, MockWsServer, WsResponse};

#[tokio::test]
async fn handshake_error_preserves_original_ws_url_and_not_mapped_http_url() {
    let server = MockWsServer::new().await.unwrap();
    let url = server.ws_url("/observability?token=query-secret");
    let handle = server.start_once(WsResponse {
        accept: AcceptMode::Wrong,
        ..WsResponse::default()
    });

    let err = Client::new()
        .unwrap()
        .websocket(url.clone())
        .connect()
        .await
        .expect_err("invalid accept must fail");

    let rendered = format!("{err:?}\n{err}");
    assert!(
        rendered.contains("ws://"),
        "error should preserve original ws URL: {rendered}"
    );
    assert!(
        !rendered.contains("http://127.0.0.1"),
        "mapped http URL should not replace original ws URL: {rendered}"
    );

    let _ = handle.await.unwrap();
}

#[tokio::test]
async fn handshake_error_redacts_websocket_key_accept_and_cookie_values() {
    let server = MockWsServer::new().await.unwrap();
    let url = server.ws_url("/redaction");
    let handle = server.start_once(WsResponse {
        accept: AcceptMode::Wrong,
        ..WsResponse::default()
    });

    let err = Client::new()
        .unwrap()
        .websocket(url)
        .header("Cookie", "session=raw-cookie-secret")
        .connect()
        .await
        .expect_err("invalid accept must fail");

    let exchange = handle.await.unwrap();
    let request_key = exchange
        .request
        .header("Sec-WebSocket-Key")
        .expect("request included key")
        .to_string();
    let rendered = format!("{err:?}\n{err}");

    assert!(
        !rendered.contains(&request_key),
        "error leaked raw Sec-WebSocket-Key: {rendered}"
    );
    assert!(
        !rendered.contains("definitely-wrong"),
        "error leaked raw Sec-WebSocket-Accept: {rendered}"
    );
    assert!(
        !rendered.contains("raw-cookie-secret"),
        "error leaked raw cookie value: {rendered}"
    );
}
