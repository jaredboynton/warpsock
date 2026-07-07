use warpsock::{Client, Message, PreparedMessage, WebSocketFrameOpcode};

#[path = "helpers/mock_ws_server.rs"]
mod mock_ws_server;

use mock_ws_server::{server_ping_frame, MockWsServer, WsResponse};

#[tokio::test]
async fn send_text_writes_masked_client_frame() {
    let server = MockWsServer::new().await.unwrap();
    let url = server.ws_url("/send-text");
    let handle = server.start_once(WsResponse {
        expected_client_frames: 1,
        ..WsResponse::default()
    });

    let mut ws = Client::new()
        .unwrap()
        .websocket(url)
        .connect()
        .await
        .expect("websocket handshake should succeed");
    ws.send_text("hello from client")
        .await
        .expect("send text frame");

    let exchange = handle.await.unwrap();
    let frame = exchange.client_frame.expect("server captured client frame");
    assert!(frame.fin);
    assert_eq!(frame.opcode, 0x1);
    assert!(
        frame.masked,
        "RFC 6455 requires all client frames to be masked"
    );
    assert_eq!(frame.payload, b"hello from client");
}

#[tokio::test]
async fn incoming_ping_writes_matching_pong_if_auto_pong_is_supported() {
    let server = MockWsServer::new().await.unwrap();
    let url = server.ws_url("/ping");
    let handle = server.start_once(WsResponse {
        first_frame: Some(server_ping_frame(b"abc")),
        expected_client_frames: 1,
        ..WsResponse::default()
    });

    let mut ws = Client::new()
        .unwrap()
        .websocket(url)
        .connect()
        .await
        .expect("websocket handshake should succeed");

    let _ = ws.next().await;
    let exchange = handle.await.unwrap();
    let frame = exchange
        .client_frame
        .expect("client should answer server ping with pong");

    assert_eq!(frame.opcode, 0xA);
    assert!(frame.masked, "client pong frames must be masked");
    assert_eq!(frame.payload, b"abc");
}

#[tokio::test]
async fn split_reader_and_writer_operate_independently() {
    let server = MockWsServer::new().await.unwrap();
    let url = server.ws_url("/split");
    let handle = server.start_once(WsResponse {
        first_frame: Some(mock_ws_server::server_text_frame("ready")),
        expected_client_frames: 1,
        ..WsResponse::default()
    });

    let ws = Client::new()
        .unwrap()
        .websocket(url)
        .connect()
        .await
        .expect("websocket handshake should succeed");
    let (mut reader, mut writer) = ws.split();

    writer
        .send_text("from split writer")
        .await
        .expect("split writer sends text");
    let message = reader
        .next()
        .await
        .expect("split reader receives")
        .expect("message available");

    assert!(matches!(message, Message::Text(text) if text == "ready"));
    let exchange = handle.await.unwrap();
    let frame = exchange.client_frame.expect("server captured client frame");
    assert_eq!(frame.opcode, 0x1);
    assert!(frame.masked);
    assert_eq!(frame.payload, b"from split writer");
}

#[tokio::test]
async fn next_frame_exposes_raw_fragment_boundaries() {
    let frame = [
        server_frame_with_fin(false, 0x1, b"he"),
        server_frame_with_fin(true, 0x0, b"llo"),
    ]
    .concat();
    let server = MockWsServer::new().await.unwrap();
    let url = server.ws_url("/next-frame");
    let handle = server.start_once(WsResponse {
        first_frame: Some(frame),
        ..WsResponse::default()
    });

    let mut ws = Client::new()
        .unwrap()
        .websocket(url)
        .connect()
        .await
        .expect("websocket handshake should succeed");

    let first = ws
        .next_frame()
        .await
        .expect("first raw frame read")
        .expect("first raw frame");
    let second = ws
        .next_frame()
        .await
        .expect("second raw frame read")
        .expect("second raw frame");

    assert!(!first.fin);
    assert_eq!(first.opcode, WebSocketFrameOpcode::Text);
    assert_eq!(first.payload, b"he".as_slice());
    assert!(second.fin);
    assert_eq!(second.opcode, WebSocketFrameOpcode::Continuation);
    assert_eq!(second.payload, b"llo".as_slice());

    let _ = handle.await.unwrap();
}

#[tokio::test]
async fn prepared_message_sends_fresh_masked_frame() {
    let server = MockWsServer::new().await.unwrap();
    let url = server.ws_url("/prepared");
    let handle = server.start_once(WsResponse {
        expected_client_frames: 1,
        ..WsResponse::default()
    });

    let mut ws = Client::new()
        .unwrap()
        .websocket(url)
        .connect()
        .await
        .expect("websocket handshake should succeed");
    let prepared = PreparedMessage::text("prepared broadcast");
    ws.send_prepared(&prepared).await.expect("send prepared");

    let exchange = handle.await.unwrap();
    let frame = exchange.client_frame.expect("server captured client frame");
    assert_eq!(frame.opcode, 0x1);
    assert!(frame.masked);
    assert_eq!(frame.payload, b"prepared broadcast");
}

#[tokio::test]
async fn prepared_batch_writes_multiple_masked_frames() {
    let server = MockWsServer::new().await.unwrap();
    let url = server.ws_url("/prepared-batch");
    let handle = server.start_once(WsResponse {
        expected_client_frames: 2,
        ..WsResponse::default()
    });

    let prepared = [
        PreparedMessage::text("first"),
        PreparedMessage::binary(Vec::from(&b"second"[..])),
    ];
    let mut ws = Client::new()
        .unwrap()
        .websocket(url)
        .connect()
        .await
        .expect("websocket handshake should succeed");
    ws.send_prepared_batch(prepared.iter())
        .await
        .expect("send prepared batch");

    let exchange = handle.await.unwrap();
    assert_eq!(exchange.client_frames.len(), 2);
    assert_eq!(exchange.client_frames[0].opcode, 0x1);
    assert!(exchange.client_frames[0].masked);
    assert_eq!(exchange.client_frames[0].payload, b"first");
    assert_eq!(exchange.client_frames[1].opcode, 0x2);
    assert!(exchange.client_frames[1].masked);
    assert_eq!(exchange.client_frames[1].payload, b"second");
}

#[tokio::test]
async fn fragmented_text_is_reassembled_and_validated_as_one_message() {
    let frame = [
        server_frame_with_fin(false, 0x1, b"he"),
        server_frame_with_fin(true, 0x0, b"llo"),
    ]
    .concat();
    let server = MockWsServer::new().await.unwrap();
    let url = server.ws_url("/fragmented-text");
    let handle = server.start_once(WsResponse {
        first_frame: Some(frame),
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
        .expect("read fragmented text")
        .expect("message available");
    assert!(matches!(message, Message::Text(text) if text == "hello"));

    let _ = handle.await.unwrap();
}

#[tokio::test]
async fn rsv_bits_trigger_protocol_close_1002() {
    expect_protocol_error_close(server_frame_raw(0xC1, b""), 1002).await;
}

#[tokio::test]
async fn unknown_opcode_triggers_protocol_close_1002() {
    expect_protocol_error_close(server_frame_raw(0x83, b""), 1002).await;
}

#[tokio::test]
async fn control_frame_fragmentation_triggers_protocol_close_1002() {
    expect_protocol_error_close(server_frame_with_fin(false, 0x9, b"ping"), 1002).await;
}

#[tokio::test]
async fn oversized_ping_triggers_protocol_close_1002() {
    expect_protocol_error_close(server_frame_with_fin(true, 0x9, &[0; 126]), 1002).await;
}

#[tokio::test]
async fn close_frame_with_one_byte_payload_triggers_protocol_close_1002() {
    expect_protocol_error_close(vec![0x88, 0x01, 0x00], 1002).await;
}

#[tokio::test]
async fn reserved_close_code_1004_triggers_protocol_close_1002() {
    expect_protocol_error_close(
        server_frame_with_fin(true, 0x8, &1004_u16.to_be_bytes()),
        1002,
    )
    .await;
}

#[tokio::test]
async fn invalid_fragmented_text_utf8_triggers_close_1007() {
    let frame = [
        server_frame_with_fin(false, 0x1, &[0xF0]),
        server_frame_with_fin(true, 0x0, b""),
    ]
    .concat();
    expect_protocol_error_close(frame, 1007).await;
}

#[tokio::test]
async fn max_message_size_violation_triggers_close_1009() {
    let server = MockWsServer::new().await.unwrap();
    let url = server.ws_url("/message-too-large");
    let handle = server.start_once(WsResponse {
        first_frame: Some(server_frame_with_fin(true, 0x1, b"abc")),
        expected_client_frames: 1,
        ..WsResponse::default()
    });

    let mut ws = Client::new()
        .unwrap()
        .websocket(url)
        .max_message_size(2)
        .connect()
        .await
        .expect("websocket handshake should succeed");

    let err = ws.next().await.expect_err("oversized message must fail");
    assert_error_mentions(&err, &["LimitExceeded", "message exceeds"]);

    let exchange = handle.await.unwrap();
    let frame = exchange.client_frame.expect("client should send close");
    assert_eq!(frame.opcode, 0x8);
    assert!(frame.masked);
    assert_eq!(close_code(&frame.payload), Some(1009));
}

#[tokio::test]
async fn non_minimal_16_bit_payload_length_triggers_protocol_close_1002() {
    expect_protocol_error_close(vec![0x82, 126, 0, 125], 1002).await;
}

#[tokio::test]
async fn non_minimal_64_bit_payload_length_triggers_protocol_close_1002() {
    expect_protocol_error_close(vec![0x82, 127, 0, 0, 0, 0, 0, 0, 0, 126], 1002).await;
}

#[tokio::test]
async fn payload_length_with_msb_set_triggers_protocol_close_1002() {
    expect_protocol_error_close(vec![0x82, 127, 0x80, 0, 0, 0, 0, 0, 0, 0], 1002).await;
}

async fn expect_protocol_error_close(first_frame: Vec<u8>, expected_close_code: u16) {
    let server = MockWsServer::new().await.unwrap();
    let url = server.ws_url("/protocol-error");
    let handle = server.start_once(WsResponse {
        first_frame: Some(first_frame),
        expected_client_frames: 1,
        ..WsResponse::default()
    });

    let mut ws = Client::new()
        .unwrap()
        .websocket(url)
        .connect()
        .await
        .expect("websocket handshake should succeed");

    let err = ws.next().await.expect_err("invalid server frame must fail");
    assert_error_mentions(&err, &["Protocol", "UTF-8", "size limit"]);

    let exchange = handle.await.unwrap();
    let frame = exchange.client_frame.expect("client should send close");
    assert_eq!(frame.opcode, 0x8);
    assert!(frame.masked);
    assert_eq!(close_code(&frame.payload), Some(expected_close_code));
}

fn server_frame_raw(first_byte: u8, payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() <= 125);

    let mut frame = Vec::with_capacity(2 + payload.len());
    frame.push(first_byte);
    frame.push(payload.len() as u8);
    frame.extend_from_slice(payload);
    frame
}

fn server_frame_with_fin(fin: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
    let first = if fin { 0x80 } else { 0x00 } | opcode;
    if payload.len() <= 125 {
        return server_frame_raw(first, payload);
    }

    assert!(payload.len() <= u16::MAX as usize);
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.push(first);
    frame.push(126);
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn close_code(payload: &[u8]) -> Option<u16> {
    if payload.len() < 2 {
        return None;
    }

    Some(u16::from_be_bytes([payload[0], payload[1]]))
}

fn assert_error_mentions<E: std::fmt::Debug + std::fmt::Display>(err: &E, needles: &[&str]) {
    let rendered = format!("{err:?}\n{err}");
    assert!(
        needles.iter().any(|needle| rendered.contains(needle)),
        "error did not mention any of {needles:?}: {rendered}"
    );
}

// ---------------------------------------------------------------------------
// Workstream B2 (WS): reserved-bit / opcode fail-closed sweep (RFC 6455 §5.2)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rsv2_bit_without_extension_triggers_protocol_close_1002() {
    // 0xA0 = FIN + RSV2 (0x20) + Pong(0xa) -> RSV2 set with no negotiated ext.
    expect_protocol_error_close(server_frame_raw(0xA0, b""), 1002).await;
}

#[tokio::test]
async fn rsv3_bit_without_extension_triggers_protocol_close_1002() {
    // 0x92 = FIN + RSV3 (0x10) + Binary(0x2) -> RSV3 set with no negotiated ext.
    expect_protocol_error_close(server_frame_raw(0x92, b""), 1002).await;
}

#[tokio::test]
async fn all_reserved_non_control_opcodes_trigger_protocol_close_1002() {
    // RFC 6455 §5.2: opcodes 0x3-0x7 are reserved for future non-control frames
    // and MUST fail the connection.
    for opcode in 0x3u8..=0x7 {
        expect_protocol_error_close(server_frame_raw(0x80 | opcode, b""), 1002).await;
    }
}

#[tokio::test]
async fn all_reserved_control_opcodes_trigger_protocol_close_1002() {
    // RFC 6455 §5.2: opcodes 0xB-0xF are reserved for future control frames
    // and MUST fail the connection.
    for opcode in 0xBu8..=0xF {
        expect_protocol_error_close(server_frame_raw(0x80 | opcode, b""), 1002).await;
    }
}

#[tokio::test]
async fn fragmented_close_control_frame_triggers_protocol_close_1002() {
    // Control frames (Close/Ping/Pong) MUST NOT be fragmented.
    expect_protocol_error_close(
        server_frame_with_fin(false, 0x8, &1000_u16.to_be_bytes()),
        1002,
    )
    .await;
}

#[tokio::test]
async fn oversized_close_control_frame_triggers_protocol_close_1002() {
    // Control frames MUST have payload <= 125 bytes; 126 bytes must fail-close.
    expect_protocol_error_close(server_frame_with_fin(true, 0x8, &[0u8; 126]), 1002).await;
}
