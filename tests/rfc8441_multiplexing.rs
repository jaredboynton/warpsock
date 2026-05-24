//! RFC 8441 multiplexing tests.
//!
//! These tests intentionally target the public API that the RFC 8441 lane is
//! expected to add. They should fail to compile until that API exists.

use bytes::Bytes;
use specter::Client;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::timeout;

mod helpers;
use helpers::mock_h2_server::{MockH2Connection, MockH2Server};
use helpers::tls::generate_cert_bundle;

async fn serve_rfc8441_tunnel_and_normal_request(
    conn: MockH2Connection,
    observed: Arc<Mutex<Vec<(u32, &'static str)>>>,
    expected_authority: String,
) {
    conn.read_preface().await.unwrap();

    let (_, frame_type, flags, _, _) = conn.read_frame().await.unwrap();
    assert_eq!(frame_type, 0x04, "client must send SETTINGS first");
    assert_eq!(flags & 0x01, 0, "first client SETTINGS must not be ACK");

    conn.send_settings(&[(0x08, 1), (0x03, 100)]).await.unwrap();
    conn.send_settings_ack().await.unwrap();

    let mut tunnel_stream_id = None;
    let mut normal_stream_id = None;

    while tunnel_stream_id.is_none() || normal_stream_id.is_none() {
        let headers = timeout(Duration::from_secs(5), conn.read_decoded_headers())
            .await
            .expect("timed out waiting for request HEADERS")
            .unwrap();

        if headers.header(":method") == Some("CONNECT") {
            headers.assert_rfc8441_websocket_connect(&expected_authority, "https", "/socket");
            assert_eq!(
                headers.flags & 0x01,
                0,
                "CONNECT HEADERS must keep stream open"
            );
            tunnel_stream_id = Some(headers.stream_id);
            observed.lock().await.push((headers.stream_id, "tunnel"));
            conn.send_headers(headers.stream_id, &[0x88], false, true)
                .await
                .unwrap();
        } else {
            assert_eq!(headers.header(":method"), Some("GET"));
            assert_eq!(headers.header(":path"), Some("/normal"));
            normal_stream_id = Some(headers.stream_id);
            observed.lock().await.push((headers.stream_id, "request"));
            conn.send_headers(headers.stream_id, &[0x88], false, true)
                .await
                .unwrap();
            conn.send_data(headers.stream_id, b"ok", true)
                .await
                .unwrap();
        }
    }

    let tunnel_stream_id = tunnel_stream_id.unwrap();
    let normal_stream_id = normal_stream_id.unwrap();
    assert_ne!(
        tunnel_stream_id, normal_stream_id,
        "RFC 8441 tunnel and normal request must use different streams"
    );
    assert_eq!(tunnel_stream_id % 2, 1);
    assert_eq!(normal_stream_id % 2, 1);
}

#[tokio::test]
async fn rfc8441_tunnel_and_normal_h2_request_share_one_connection() {
    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();

    let server = MockH2Server::new().await.unwrap();
    let base_url = server.url_tls();
    let authority = format!("127.0.0.1:{}", server.port());
    let observed = Arc::new(Mutex::new(Vec::new()));
    let observed_for_server = observed.clone();

    server.start_tls(acceptor, move |conn| {
        serve_rfc8441_tunnel_and_normal_request(
            conn,
            observed_for_server.clone(),
            authority.clone(),
        )
    });

    let client = Client::builder()
        .add_root_certificate(ca_cert)
        .prefer_http2(true)
        .build()
        .unwrap();

    let tunnel_url = format!("{base_url}/socket").replace("https://", "wss://");
    let normal_url = format!("{base_url}/normal");

    let tunnel = timeout(
        Duration::from_secs(5),
        client.websocket_h2(&tunnel_url).open(),
    )
    .await
    .expect("RFC 8441 tunnel open timed out")
    .expect("RFC 8441 tunnel should open over ALPN h2");

    let response = timeout(
        Duration::from_secs(5),
        client.get(normal_url.as_str()).send(),
    )
    .await
    .expect("normal request timed out")
    .expect("normal H2 request should complete while tunnel is open");

    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(
        response.buffered_bytes().unwrap_or(&Bytes::new()).as_ref(),
        b"ok"
    );
    drop(tunnel);

    let observed = observed.lock().await;
    assert_eq!(observed.len(), 2, "server should see both streams");
    assert!(observed.iter().any(|(_, kind)| *kind == "tunnel"));
    assert!(observed.iter().any(|(_, kind)| *kind == "request"));
}
