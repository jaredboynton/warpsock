use std::sync::{Arc, Mutex};

use boring::ssl::{select_next_proto, AlpnError, SslAcceptor};
use specter::{Client, CookieJar, Message};
use tokio::sync::RwLock;

#[path = "helpers/mock_ws_server.rs"]
mod mock_ws_server;
#[path = "helpers/tls.rs"]
mod tls;

use mock_ws_server::{server_text_frame, AcceptMode, MockWsServer, WsResponse};
use tls::generate_cert_bundle;

#[tokio::test]
async fn valid_ws_handshake_sends_required_headers_and_16_byte_key() {
    let server = MockWsServer::new().await.unwrap();
    let url = server.ws_url("/chat?room=blue");
    let expected_host = url
        .strip_prefix("ws://")
        .unwrap()
        .strip_suffix("/chat?room=blue")
        .unwrap()
        .to_string();
    let handle = server.start_once(WsResponse::default());

    let _ws = Client::new()
        .unwrap()
        .websocket(url)
        .connect()
        .await
        .expect("websocket handshake should succeed");

    let exchange = handle.await.unwrap();
    let request = exchange.request;

    assert_eq!(request.request_line, "GET /chat?room=blue HTTP/1.1");
    assert_eq!(request.header("Host"), Some(expected_host.as_str()));
    assert_eq!(request.header("Upgrade"), Some("websocket"));
    assert!(request
        .header("Connection")
        .unwrap_or_default()
        .split(',')
        .any(|token| token.trim().eq_ignore_ascii_case("upgrade")));
    assert_eq!(request.header("Sec-WebSocket-Version"), Some("13"));
    assert_eq!(request.sec_websocket_key_len(), 16);
    assert_eq!(request.header("Sec-WebSocket-Extensions"), None);
}

#[tokio::test]
async fn explicit_ws_port_is_preserved_in_host_header() {
    let server = MockWsServer::new().await.unwrap();
    let url = server.ws_url("/port");
    let expected_host = url
        .strip_prefix("ws://")
        .unwrap()
        .strip_suffix("/port")
        .unwrap()
        .to_string();
    let handle = server.start_once(WsResponse::default());

    let _ws = Client::new()
        .unwrap()
        .websocket(url)
        .connect()
        .await
        .expect("websocket handshake should succeed");

    let exchange = handle.await.unwrap();
    assert_eq!(
        exchange.request.header("Host"),
        Some(expected_host.as_str())
    );
}

#[tokio::test]
async fn wrong_accept_header_fails_the_handshake() {
    let server = MockWsServer::new().await.unwrap();
    let url = server.ws_url("/bad-accept");
    let handle = server.start_once(WsResponse {
        accept: AcceptMode::Wrong,
        expected_client_frames: 1,
        ..WsResponse::default()
    });

    let err = Client::new()
        .unwrap()
        .websocket(url)
        .connect()
        .await
        .expect_err("invalid Sec-WebSocket-Accept must fail");

    let debug = format!("{err:?}");
    assert!(
        debug.contains("InvalidAccept") || debug.contains("Sec-WebSocket-Accept"),
        "unexpected error: {debug}"
    );
    assert!(handle.await.unwrap().client_frame.is_none());
}

#[tokio::test]
async fn unexpected_extension_header_fails_the_handshake() {
    let server = MockWsServer::new().await.unwrap();
    let url = server.ws_url("/extension");
    let handle = server.start_once(WsResponse {
        headers: vec![(
            "Sec-WebSocket-Extensions".to_string(),
            "permessage-deflate".to_string(),
        )],
        expected_client_frames: 1,
        ..WsResponse::default()
    });

    let err = Client::new()
        .unwrap()
        .websocket(url)
        .connect()
        .await
        .expect_err("unexpected extension must fail");

    let debug = format!("{err:?}");
    assert!(
        debug.contains("UnexpectedExtension") || debug.contains("Sec-WebSocket-Extensions"),
        "unexpected error: {debug}"
    );
    assert!(handle.await.unwrap().client_frame.is_none());
}

#[tokio::test]
async fn unexpected_subprotocol_header_fails_when_none_was_offered() {
    let server = MockWsServer::new().await.unwrap();
    let url = server.ws_url("/subprotocol");
    let handle = server.start_once(WsResponse {
        headers: vec![("Sec-WebSocket-Protocol".to_string(), "chat".to_string())],
        expected_client_frames: 1,
        ..WsResponse::default()
    });

    let err = Client::new()
        .unwrap()
        .websocket(url)
        .connect()
        .await
        .expect_err("unoffered subprotocol must fail");

    let debug = format!("{err:?}");
    assert!(
        debug.contains("UnexpectedSubprotocol") || debug.contains("Sec-WebSocket-Protocol"),
        "unexpected error: {debug}"
    );
    assert!(handle.await.unwrap().client_frame.is_none());
}

#[tokio::test]
async fn offered_subprotocol_is_accepted_when_echoed_exactly() {
    let server = MockWsServer::new().await.unwrap();
    let url = server.ws_url("/subprotocol-ok");
    let handle = server.start_once(WsResponse {
        headers: vec![("Sec-WebSocket-Protocol".to_string(), "chat.v2".to_string())],
        ..WsResponse::default()
    });

    let ws = Client::new()
        .unwrap()
        .websocket(url)
        .subprotocol("chat.v2")
        .connect()
        .await
        .expect("offered subprotocol should succeed");

    assert_eq!(ws.protocol(), Some("chat.v2"));
    let exchange = handle.await.unwrap();
    assert_eq!(
        exchange.request.header("Sec-WebSocket-Protocol"),
        Some("chat.v2")
    );
}

#[tokio::test]
async fn first_frame_sent_with_101_is_available_to_next() {
    let server = MockWsServer::new().await.unwrap();
    let url = server.ws_url("/early-frame");
    let handle = server.start_once(WsResponse {
        first_frame: Some(server_text_frame("ready")),
        ..WsResponse::default()
    });

    let mut ws = Client::new()
        .unwrap()
        .websocket(url)
        .connect()
        .await
        .expect("websocket handshake should succeed");

    let message = ws
        .next()
        .await
        .expect("read first frame")
        .expect("message available");
    assert!(matches!(message, Message::Text(text) if text == "ready"));

    let _ = handle.await.unwrap();
}

#[tokio::test]
async fn wss_handshake_offers_only_http1_alpn() {
    let server = MockWsServer::new().await.unwrap();
    let url = server.wss_url("/secure-alpn");
    let (acceptor, ca_cert, client_alpn) = h1_tls_acceptor();
    let handle = server.start_tls_once(acceptor, WsResponse::default());

    let ws = Client::builder()
        .add_root_certificate(ca_cert)
        .localhost_allows_invalid_certs(false)
        .build()
        .unwrap()
        .websocket(url)
        .connect()
        .await
        .expect("wss websocket handshake should succeed");
    drop(ws);

    let exchange = handle.await.unwrap();
    assert_eq!(&*client_alpn.lock().unwrap(), b"\x08http/1.1");
    assert_eq!(
        exchange.selected_alpn.as_deref(),
        Some(b"http/1.1".as_ref())
    );
}

#[tokio::test]
async fn wss_set_cookie_on_101_is_stored_and_replayed() {
    let cookie_jar = Arc::new(RwLock::new(CookieJar::new()));
    let (acceptor1, ca_cert1, _) = h1_tls_acceptor();
    let (acceptor2, ca_cert2, _) = h1_tls_acceptor();

    let server1 = MockWsServer::new().await.unwrap();
    let url1 = server1.wss_url("/set-cookie");
    let handle1 = server1.start_tls_once(
        acceptor1,
        WsResponse {
            headers: vec![(
                "Set-Cookie".to_string(),
                "sid=abc; Secure; Path=/".to_string(),
            )],
            ..WsResponse::default()
        },
    );

    let client = Client::builder()
        .add_root_certificate(ca_cert1)
        .add_root_certificate(ca_cert2)
        .cookie_jar(cookie_jar)
        .build()
        .unwrap();

    let ws = client
        .websocket(url1)
        .connect()
        .await
        .expect("first wss handshake should store cookie");
    drop(ws);
    let _ = handle1.await.unwrap();

    let server2 = MockWsServer::new().await.unwrap();
    let url2 = server2.wss_url("/uses-cookie");
    let handle2 = server2.start_tls_once(acceptor2, WsResponse::default());

    let ws = client
        .websocket(url2)
        .connect()
        .await
        .expect("second wss handshake should send cookie");
    drop(ws);

    let exchange = handle2.await.unwrap();
    assert_eq!(exchange.request.header("Cookie"), Some("sid=abc"));
}

#[tokio::test]
async fn explicit_wss_cookie_header_is_not_overwritten_by_cookie_jar() {
    let cookie_jar = Arc::new(RwLock::new(CookieJar::new()));
    let (acceptor1, ca_cert1, _) = h1_tls_acceptor();
    let (acceptor2, ca_cert2, _) = h1_tls_acceptor();

    let server1 = MockWsServer::new().await.unwrap();
    let url1 = server1.wss_url("/set-cookie");
    let handle1 = server1.start_tls_once(
        acceptor1,
        WsResponse {
            headers: vec![(
                "Set-Cookie".to_string(),
                "sid=abc; Secure; Path=/".to_string(),
            )],
            ..WsResponse::default()
        },
    );

    let client = Client::builder()
        .add_root_certificate(ca_cert1)
        .add_root_certificate(ca_cert2)
        .cookie_jar(cookie_jar)
        .build()
        .unwrap();

    let ws = client
        .websocket(url1)
        .connect()
        .await
        .expect("first wss handshake should store cookie");
    drop(ws);
    let _ = handle1.await.unwrap();

    let server2 = MockWsServer::new().await.unwrap();
    let url2 = server2.wss_url("/manual-cookie");
    let handle2 = server2.start_tls_once(acceptor2, WsResponse::default());

    let ws = client
        .websocket(url2)
        .header("Cookie", "manual=1")
        .connect()
        .await
        .expect("second wss handshake should respect explicit cookie header");
    drop(ws);

    let exchange = handle2.await.unwrap();
    assert_eq!(exchange.request.header("Cookie"), Some("manual=1"));
}

fn h1_tls_acceptor() -> (SslAcceptor, Vec<u8>, Arc<Mutex<Vec<u8>>>) {
    let (mut builder, ca_cert) = generate_cert_bundle();
    let client_alpn = Arc::new(Mutex::new(Vec::new()));
    let captured_alpn = Arc::clone(&client_alpn);

    builder.set_alpn_select_callback(move |_, client_protos| {
        *captured_alpn.lock().unwrap() = client_protos.to_vec();
        select_next_proto(b"\x08http/1.1", client_protos).ok_or(AlpnError::NOACK)
    });

    (builder.build(), ca_cert, client_alpn)
}
