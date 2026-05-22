use specter::transport::h3::{DriverCommand, H3Handle};
use specter::{Client, Error};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::sync::mpsc;

#[tokio::test]
async fn rfc9220_handle_open_websocket_tunnel_sends_driver_command() {
    let (command_tx, mut command_rx) = mpsc::channel(1);
    let handle = H3Handle::new(command_tx, Arc::new(AtomicBool::new(false)));
    let uri: http::Uri = "https://example.com/chat".parse().unwrap();

    let open = tokio::spawn({
        let uri = uri.clone();
        async move {
            handle
                .open_websocket_tunnel(uri, vec![("origin".into(), "https://app".into())])
                .await
        }
    });

    match command_rx
        .recv()
        .await
        .expect("H3 handle must send driver command")
    {
        DriverCommand::OpenWebSocketTunnel {
            uri: command_uri,
            headers,
            response_tx,
        } => {
            assert_eq!(command_uri, uri);
            assert_eq!(headers, vec![("origin".into(), "https://app".into())]);
            response_tx
                .send(Err(Error::HttpProtocol("done".into())))
                .unwrap();
        }
        other => panic!("unexpected command: {other:?}"),
    }

    let err = open
        .await
        .unwrap()
        .expect_err("test response should fail the open");
    assert!(err.to_string().contains("done"));
}

#[tokio::test]
async fn rfc9220_client_builder_exposes_websocket_h3() {
    let client = Client::builder().build().unwrap();
    let err = client
        .websocket_h3("https://example.com/chat")
        .open()
        .await
        .expect_err("non-WebSocket scheme must fail before network I/O");

    assert!(
        matches!(err, Error::WebSocketUnsupported(_)),
        "unexpected error: {err:?}"
    );
}
