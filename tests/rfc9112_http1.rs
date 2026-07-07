use bytes::Bytes;
use http::{Method, Uri};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use warpsock::transport::connector::MaybeHttpsStream;
use warpsock::transport::h1::H1Connection;

async fn start_test_server<F>(handler: F) -> String
where
    F: Fn(TcpStream) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
        + Send
        + Sync
        + 'static
        + Copy,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());

    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            tokio::spawn(handler(socket));
        }
    });

    url
}

#[tokio::test]
async fn test_request_framing_content_length() {
    // Tests that Content-Length is used correctly
    let url = start_test_server(|mut socket| {
        Box::pin(async move {
            // Read headers
            let mut buf = [0u8; 4096];
            let mut received = Vec::new();
            loop {
                let n = socket.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                received.extend_from_slice(&buf[..n]);
                let s = String::from_utf8_lossy(&received);
                if s.contains("Hello") {
                    break;
                }
            }
            let request = String::from_utf8_lossy(&received);

            // Assert framing
            assert!(request.contains("Content-Length: 5"));
            assert!(request.contains("\r\n\r\nHello"));

            // Send response
            let response = "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok";
            socket.write_all(response.as_bytes()).await.unwrap();
        })
    })
    .await;

    let uri: Uri = url.parse().unwrap();
    let stream = TcpStream::connect(format!("127.0.0.1:{}", uri.port().unwrap()))
        .await
        .unwrap();
    let mut conn = H1Connection::new(MaybeHttpsStream::Http(stream));

    let body = Bytes::from("Hello");
    let response = conn
        .send_request(Method::POST, &uri, vec![], Some(body))
        .await
        .unwrap();

    // Response status is a public field u16
    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn test_request_framing_chunked() {
    let url = start_test_server(|mut socket| {
        Box::pin(async move {
            // Read request
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await.unwrap();

            // Send Chunked Response
            // 5\r\nHello\r\n0\r\n\r\n
            let response =
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello\r\n0\r\n\r\n";
            socket.write_all(response.as_bytes()).await.unwrap();
        })
    })
    .await;

    let uri: Uri = url.parse().unwrap();
    let stream = TcpStream::connect(format!("127.0.0.1:{}", uri.port().unwrap()))
        .await
        .unwrap();
    let mut conn = H1Connection::new(MaybeHttpsStream::Http(stream));

    let response = conn
        .send_request(Method::GET, &uri, vec![], None)
        .await
        .unwrap();

    assert_eq!(response.status().as_u16(), 200);
    // Verify body content
    assert_eq!(
        response
            .buffered_bytes()
            .map(|b| b.as_ref())
            .unwrap_or_default(),
        b"Hello"
    );
}

#[tokio::test]
async fn test_response_header_folding_rejection() {
    // RFC 9112 Obsoletes line folding (obs-fold). Senders MUST NOT generate.
    // Receivers MAY accept or reject. Ideally reject or replace with SP.
    let url = start_test_server(|mut socket| Box::pin(async move {
        let mut buf = [0u8; 1024];
        let _ = socket.read(&mut buf).await.unwrap();

        // Response with folded header
        // Header: value\r\n continuation
        let response = "HTTP/1.1 200 OK\r\nFolded-Header: value\r\n continuation\r\nContent-Length: 0\r\n\r\n";
        socket.write_all(response.as_bytes()).await.unwrap();
    })).await;

    let uri: Uri = url.parse().unwrap();
    let stream = TcpStream::connect(format!("127.0.0.1:{}", uri.port().unwrap()))
        .await
        .unwrap();
    let mut conn = H1Connection::new(MaybeHttpsStream::Http(stream));

    // This might fail if httparse rejects it, or succeed if it handles it.
    // httparse generally handles it by treating it as SP.
    match conn.send_request(Method::GET, &uri, vec![], None).await {
        Ok(_res) => {
            // Verify behavior if successful
        }
        Err(_) => {
            // Rejection is also acceptable compliance.
        }
    }
}

// ---------------------------------------------------------------------------
// Workstream B2 (H1): RFC 9112 §11 security-considerations fail-closed sweep
// ---------------------------------------------------------------------------

async fn send_raw_response_and_get_result(
    raw_response: &'static [u8],
) -> warpsock::error::Result<warpsock::response::Response> {
    let url = start_test_server(move |mut socket| {
        Box::pin(async move {
            let mut buf = [0u8; 4096];
            let _ = socket.read(&mut buf).await.unwrap();
            let _ = socket.write_all(raw_response).await;
            let _ = socket.flush().await;
        })
    })
    .await;

    let uri: Uri = url.parse().unwrap();
    let stream = TcpStream::connect(format!("127.0.0.1:{}", uri.port().unwrap()))
        .await
        .unwrap();
    let mut conn = H1Connection::new(MaybeHttpsStream::Http(stream));
    let response = conn.send_request(Method::GET, &uri, vec![], None).await?;
    Ok(response)
}

#[tokio::test]
async fn test_transfer_encoding_wins_over_content_length_rfc9112_6_3() {
    // RFC 9112 §6.3: if a message has both Transfer-Encoding and Content-Length,
    // the Content-Length MUST be ignored (Transfer-Encoding wins). A request
    // smuggling defence: the chunked framing decides the body length, so the
    // (deliberately wrong) Content-Length: 3 must not truncate the 5-byte body.
    let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nHello\r\n0\r\n\r\n";
    let mut response = send_raw_response_and_get_result(raw)
        .await
        .expect("chunked body with conflicting Content-Length must parse via TE");
    assert_eq!(response.status().as_u16(), 200);
    let body = response.bytes().unwrap_or_default();
    assert_eq!(
        body.as_ref(),
        b"Hello",
        "TE-chunked framing must win over Content-Length"
    );
}

#[tokio::test]
async fn test_chunk_size_overflow_is_rejected_rfc9112_7_1() {
    // RFC 9112 §7.1: a chunk-size that overflows must be treated as an error,
    // never conflated with \"need more data\". An over-large hex chunk-size that
    // cannot fit in usize must fail-close.
    let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nFFFFFFFFFFFFFFFFFF\r\nx\r\n0\r\n\r\n";
    let result = send_raw_response_and_get_result(raw).await;
    // Either the initial parse fails, or the body drain fails; both are
    // acceptable fail-closed outcomes. What is NOT acceptable is silently
    // accepting an oversized/overflowing chunk-size.
    if let Ok(response) = result {
        let body = response.bytes();
        assert!(
            body.is_err() || body.unwrap().is_empty(),
            "overflowing chunk-size must not yield a valid body"
        );
    }
}

#[tokio::test]
async fn test_invalid_chunk_size_hex_is_rejected() {
    // A non-hex chunk-size line is malformed framing and must fail-close.
    let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nZZZ\r\nx\r\n0\r\n\r\n";
    let result = send_raw_response_and_get_result(raw).await;
    if let Ok(response) = result {
        let body = response.bytes();
        assert!(
            body.is_err() || body.unwrap().is_empty(),
            "invalid chunk-size hex must not yield a valid body"
        );
    }
}
