//! RFC 7692 permessage-deflate negotiation completeness.
//!
//! Exercises the public WebSocket builder surface against a mock server that
//! echoes (or corrupts) the `Sec-WebSocket-Extensions` response so we can assert
//! offer serialization, the acceptance matrix from RFC 7692 §7.1, and the
//! rejection matrix for malformed / unsolicited parameters (§5-§7).

use flate2::{Compress, Compression, FlushCompress};
use warpsock::websocket::PermessageDeflateOffer;
use warpsock::{Client, Message};

#[path = "helpers/mock_ws_server.rs"]
mod mock_ws_server;

use mock_ws_server::{MockWsServer, WsResponse};

fn ext_header(value: &str) -> Vec<(String, String)> {
    vec![("Sec-WebSocket-Extensions".to_string(), value.to_string())]
}

fn deflate_message(payload: &[u8]) -> Vec<u8> {
    let mut encoder = Compress::new(Compression::fast(), false);
    let mut out = Vec::with_capacity(payload.len().saturating_mul(2).max(32));
    encoder
        .compress_vec(payload, &mut out, FlushCompress::Sync)
        .unwrap();
    if out.ends_with(&[0x00, 0x00, 0xff, 0xff]) {
        out.truncate(out.len() - 4);
    }
    out
}

fn server_compressed_text_frame(text: &str) -> Vec<u8> {
    let payload = deflate_message(text.as_bytes());
    assert!(
        payload.len() <= 125,
        "test helper only supports small frames"
    );
    let mut frame = Vec::with_capacity(2 + payload.len());
    frame.push(0xc1); // FIN + RSV1 + text opcode
    frame.push(payload.len() as u8);
    frame.extend_from_slice(&payload);
    frame
}

// --- Offer serialization ---------------------------------------------------

#[tokio::test]
async fn default_builder_offers_no_context_takeover() {
    let server = MockWsServer::new().await.unwrap();
    let url = server.ws_url("/offer-default");
    let handle = server.start_once(WsResponse {
        headers: ext_header(
            "permessage-deflate; server_no_context_takeover; client_no_context_takeover",
        ),
        ..WsResponse::default()
    });

    let _ws = Client::new()
        .unwrap()
        .websocket(url)
        .permessage_deflate()
        .connect()
        .await
        .expect("handshake should succeed");

    let exchange = handle.await.unwrap();
    assert_eq!(
        exchange.request.header("Sec-WebSocket-Extensions"),
        Some("permessage-deflate; client_no_context_takeover; server_no_context_takeover"),
    );
}

#[tokio::test]
async fn chrome_style_offer_advertises_client_max_window_bits() {
    let server = MockWsServer::new().await.unwrap();
    let url = server.ws_url("/offer-chrome");
    let handle = server.start_once(WsResponse {
        // Server accepts by echoing the bare extension (valueless).
        headers: ext_header("permessage-deflate"),
        ..WsResponse::default()
    });

    let _ws = Client::new()
        .unwrap()
        .websocket(url)
        .permessage_deflate_with(PermessageDeflateOffer::default())
        .connect()
        .await
        .expect("handshake should succeed");

    let exchange = handle.await.unwrap();
    assert_eq!(
        exchange.request.header("Sec-WebSocket-Extensions"),
        Some("permessage-deflate; client_max_window_bits"),
    );
}

#[tokio::test]
async fn custom_offer_serializes_all_parameters() {
    let server = MockWsServer::new().await.unwrap();
    let url = server.ws_url("/offer-custom");
    let handle = server.start_once(WsResponse {
        headers: ext_header("permessage-deflate; server_max_window_bits=12"),
        ..WsResponse::default()
    });

    let offer = PermessageDeflateOffer {
        offer_client_max_window_bits: true,
        server_max_window_bits: Some(12),
        client_no_context_takeover: true,
        server_no_context_takeover: false,
    };

    let _ws = Client::new()
        .unwrap()
        .websocket(url)
        .permessage_deflate_with(offer)
        .connect()
        .await
        .expect("handshake should succeed");

    let exchange = handle.await.unwrap();
    assert_eq!(
        exchange.request.header("Sec-WebSocket-Extensions"),
        Some("permessage-deflate; client_no_context_takeover; client_max_window_bits; server_max_window_bits=12"),
    );
}

// --- Acceptance matrix (RFC 7692 §7.1 valid responses) ---------------------

async fn assert_accepts(path: &str, offer: PermessageDeflateOffer, response_ext: &str) {
    let server = MockWsServer::new().await.unwrap();
    let url = server.ws_url(path);
    let handle = server.start_once(WsResponse {
        headers: ext_header(response_ext),
        ..WsResponse::default()
    });

    let _ws = Client::new()
        .unwrap()
        .websocket(url)
        .permessage_deflate_with(offer)
        .connect()
        .await
        .unwrap_or_else(|err| panic!("response {response_ext:?} should be accepted: {err:?}"));

    let _ = handle.await.unwrap();
}

#[tokio::test]
async fn accepts_server_max_window_bits_full_range() {
    for bits in 8..=15 {
        let offer = PermessageDeflateOffer {
            offer_client_max_window_bits: true,
            server_max_window_bits: Some(15),
            client_no_context_takeover: false,
            server_no_context_takeover: false,
        };
        assert_accepts(
            &format!("/accept-server-{bits}"),
            offer,
            &format!("permessage-deflate; server_max_window_bits={bits}"),
        )
        .await;
    }
}

#[tokio::test]
async fn accepts_client_max_window_bits_full_range() {
    for bits in 8..=15 {
        assert_accepts(
            &format!("/accept-client-{bits}"),
            PermessageDeflateOffer::default(),
            &format!("permessage-deflate; client_max_window_bits={bits}"),
        )
        .await;
    }
}

#[tokio::test]
async fn accepts_valueless_client_max_window_bits_in_response() {
    assert_accepts(
        "/accept-valueless-client",
        PermessageDeflateOffer::default(),
        "permessage-deflate; client_max_window_bits",
    )
    .await;
}

#[tokio::test]
async fn accepts_echoed_no_context_takeover() {
    assert_accepts(
        "/accept-ncto",
        PermessageDeflateOffer::no_context_takeover(),
        "permessage-deflate; client_no_context_takeover; server_no_context_takeover",
    )
    .await;
}

// --- Rejection matrix (RFC 7692 §5-§7 malformed / unsolicited) --------------

async fn assert_rejects(path: &str, offer: PermessageDeflateOffer, response_ext: &str) {
    let server = MockWsServer::new().await.unwrap();
    let url = server.ws_url(path);
    let handle = server.start_once(WsResponse {
        headers: ext_header(response_ext),
        ..WsResponse::default()
    });

    let err = Client::new()
        .unwrap()
        .websocket(url)
        .permessage_deflate_with(offer)
        .connect()
        .await
        .err()
        .unwrap_or_else(|| panic!("response {response_ext:?} must be rejected"));
    let debug = format!("{err:?}");
    assert!(
        debug.contains("Protocol") || debug.contains("Extension"),
        "unexpected error kind for {response_ext:?}: {debug}",
    );

    let _ = handle.await.unwrap();
}

#[tokio::test]
async fn rejects_window_bits_below_range() {
    assert_rejects(
        "/reject-bits-7",
        PermessageDeflateOffer::default(),
        "permessage-deflate; server_max_window_bits=7",
    )
    .await;
}

#[tokio::test]
async fn rejects_window_bits_above_range() {
    assert_rejects(
        "/reject-bits-16",
        PermessageDeflateOffer::default(),
        "permessage-deflate; server_max_window_bits=16",
    )
    .await;
}

#[tokio::test]
async fn rejects_garbage_window_bits() {
    assert_rejects(
        "/reject-bits-garbage",
        PermessageDeflateOffer::default(),
        "permessage-deflate; server_max_window_bits=abc",
    )
    .await;
}

#[tokio::test]
async fn rejects_duplicate_parameter() {
    assert_rejects(
        "/reject-dup",
        PermessageDeflateOffer::no_context_takeover(),
        "permessage-deflate; server_no_context_takeover; server_no_context_takeover",
    )
    .await;
}

#[tokio::test]
async fn rejects_unsolicited_client_max_window_bits() {
    // Offer omits client_max_window_bits, so the server MUST NOT return it.
    let offer = PermessageDeflateOffer {
        offer_client_max_window_bits: false,
        server_max_window_bits: None,
        client_no_context_takeover: true,
        server_no_context_takeover: true,
    };
    assert_rejects(
        "/reject-unsolicited",
        offer,
        "permessage-deflate; client_max_window_bits=10",
    )
    .await;
}

#[tokio::test]
async fn rejects_unknown_parameter() {
    assert_rejects(
        "/reject-unknown",
        PermessageDeflateOffer::default(),
        "permessage-deflate; totally_made_up_param",
    )
    .await;
}

#[tokio::test]
async fn rejects_server_max_window_bits_exceeding_offer() {
    let offer = PermessageDeflateOffer {
        offer_client_max_window_bits: true,
        server_max_window_bits: Some(10),
        client_no_context_takeover: false,
        server_no_context_takeover: false,
    };
    assert_rejects(
        "/reject-exceeds-offer",
        offer,
        "permessage-deflate; server_max_window_bits=12",
    )
    .await;
}

// --- Loopback roundtrip ----------------------------------------------------

#[tokio::test]
async fn negotiated_window_bits_decodes_compressed_frame() {
    let server = MockWsServer::new().await.unwrap();
    let url = server.ws_url("/roundtrip");
    let handle = server.start_once(WsResponse {
        headers: ext_header(
            "permessage-deflate; client_max_window_bits=15; server_max_window_bits=15",
        ),
        first_frame: Some(server_compressed_text_frame("negotiated deflate roundtrip")),
        ..WsResponse::default()
    });

    let offer = PermessageDeflateOffer {
        offer_client_max_window_bits: true,
        server_max_window_bits: Some(15),
        client_no_context_takeover: false,
        server_no_context_takeover: false,
    };

    let mut ws = Client::new()
        .unwrap()
        .websocket(url)
        .permessage_deflate_with(offer)
        .connect()
        .await
        .expect("handshake should succeed");

    let message = ws
        .next()
        .await
        .expect("read compressed frame")
        .expect("message available");
    assert!(
        matches!(message, Message::Text(ref text) if text == "negotiated deflate roundtrip"),
        "unexpected message: {message:?}",
    );

    let _ = handle.await.unwrap();
}
