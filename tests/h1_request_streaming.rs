use bytes::Bytes;
use futures_core::Stream;
use specter::{Client, Error, HttpVersion, RedirectPolicy};
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::task::{Context, Poll};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

#[derive(Clone, Debug)]
struct CapturedRequest {
    path: String,
    headers: Vec<(String, String)>,
    raw_body: Vec<u8>,
    decoded_body: Vec<u8>,
}

struct H1UploadFixture {
    url: String,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
}

impl H1UploadFixture {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let requests_for_task = requests.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let requests = requests_for_task.clone();
                tokio::spawn(handle_connection(stream, requests));
            }
        });
        Self { url, requests }
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}{}", self.url, path)
    }

    async fn requests(&self) -> Vec<CapturedRequest> {
        self.requests.lock().await.clone()
    }
}

#[derive(Clone)]
struct CountingStream {
    chunks: Vec<Bytes>,
    polls: Arc<AtomicUsize>,
    cursor: usize,
}

impl CountingStream {
    fn new(chunks: &[&'static [u8]], polls: Arc<AtomicUsize>) -> Self {
        Self {
            chunks: chunks
                .iter()
                .map(|chunk| Bytes::from_static(chunk))
                .collect(),
            polls,
            cursor: 0,
        }
    }
}

impl Stream for CountingStream {
    type Item = Result<Bytes, Error>;

    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        if self.cursor >= self.chunks.len() {
            return Poll::Ready(None);
        }
        let chunk = self.chunks[self.cursor].clone();
        self.cursor += 1;
        Poll::Ready(Some(Ok(chunk)))
    }
}

async fn handle_connection(mut stream: TcpStream, requests: Arc<Mutex<Vec<CapturedRequest>>>) {
    let mut buffer = Vec::new();
    loop {
        let mut read_buf = [0u8; 1024];
        while !buffer.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = match stream.read(&mut read_buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            buffer.extend_from_slice(&read_buf[..n]);
        }

        let header_end = buffer.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let header_bytes = buffer[..header_end].to_vec();
        let request_text = String::from_utf8_lossy(&header_bytes);
        let path = request_text
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap_or("/")
            .to_string();
        let headers = request_text
            .lines()
            .skip(1)
            .filter_map(|line| {
                let (name, value) = line.split_once(':')?;
                Some((name.to_ascii_lowercase(), value.trim().to_string()))
            })
            .collect::<Vec<_>>();
        buffer.drain(..header_end);

        let is_chunked = header_value(&headers, "transfer-encoding")
            .map(|value| value.eq_ignore_ascii_case("chunked"))
            .unwrap_or(false);
        let content_length =
            header_value(&headers, "content-length").and_then(|value| value.parse::<usize>().ok());

        let (raw_body, decoded_body) = if is_chunked {
            read_chunked_request_body(&mut stream, &mut buffer).await
        } else if let Some(len) = content_length {
            read_sized_request_body(&mut stream, &mut buffer, len).await
        } else {
            (Vec::new(), Vec::new())
        };

        requests.lock().await.push(CapturedRequest {
            path: path.clone(),
            headers,
            raw_body,
            decoded_body,
        });

        if path == "/redirect" {
            stream
                .write_all(
                    b"HTTP/1.1 307 Temporary Redirect\r\nLocation: /final\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
                )
                .await
                .unwrap();
        } else {
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok",
                )
                .await
                .unwrap();
        }
        stream.flush().await.unwrap();
    }
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

async fn read_sized_request_body(
    stream: &mut TcpStream,
    buffer: &mut Vec<u8>,
    len: usize,
) -> (Vec<u8>, Vec<u8>) {
    while buffer.len() < len {
        let mut read_buf = [0u8; 1024];
        let n = stream.read(&mut read_buf).await.unwrap();
        if n == 0 {
            break;
        }
        buffer.extend_from_slice(&read_buf[..n]);
    }
    let body = buffer.drain(..len).collect::<Vec<_>>();
    (body.clone(), body)
}

async fn read_chunked_request_body(
    stream: &mut TcpStream,
    buffer: &mut Vec<u8>,
) -> (Vec<u8>, Vec<u8>) {
    let mut raw = Vec::new();
    let mut decoded = Vec::new();
    loop {
        while !buffer.windows(2).any(|w| w == b"\r\n") {
            let mut read_buf = [0u8; 1024];
            let n = stream.read(&mut read_buf).await.unwrap();
            if n == 0 {
                return (raw, decoded);
            }
            buffer.extend_from_slice(&read_buf[..n]);
        }

        let line_end = buffer.windows(2).position(|w| w == b"\r\n").unwrap() + 2;
        let size_line = buffer[..line_end].to_vec();
        raw.extend_from_slice(&size_line);
        let size_text = String::from_utf8_lossy(&size_line[..line_end - 2]);
        let size = usize::from_str_radix(size_text.trim(), 16).unwrap();
        buffer.drain(..line_end);

        if size == 0 {
            while buffer.len() < 2 {
                let mut read_buf = [0u8; 1024];
                let n = stream.read(&mut read_buf).await.unwrap();
                if n == 0 {
                    return (raw, decoded);
                }
                buffer.extend_from_slice(&read_buf[..n]);
            }
            raw.extend_from_slice(&buffer[..2]);
            buffer.drain(..2);
            return (raw, decoded);
        }

        while buffer.len() < size + 2 {
            let mut read_buf = [0u8; 1024];
            let n = stream.read(&mut read_buf).await.unwrap();
            if n == 0 {
                return (raw, decoded);
            }
            buffer.extend_from_slice(&read_buf[..n]);
        }
        raw.extend_from_slice(&buffer[..size + 2]);
        decoded.extend_from_slice(&buffer[..size]);
        buffer.drain(..size + 2);
    }
}

async fn collect(mut response: specter::Response) -> Vec<u8> {
    let mut body = Vec::new();
    while let Some(frame) = response.body_mut().frame().await {
        body.extend_from_slice(&frame.unwrap().into_data().unwrap());
    }
    body
}

#[tokio::test]
async fn h1_request_stream_chunked_and_sized_framing() {
    let fixture = H1UploadFixture::start().await;
    let client = Client::builder().prefer_http2(false).build().unwrap();

    let unknown_polls = Arc::new(AtomicUsize::new(0));
    let response = client
        .post(fixture.endpoint("/unknown"))
        .version(HttpVersion::Http1_1)
        .body_stream(CountingStream::new(&[b"abc", b"de"], unknown_polls.clone()))
        .send_streaming()
        .await
        .unwrap();
    assert_eq!(collect(response).await, b"ok");

    let sized_polls = Arc::new(AtomicUsize::new(0));
    let response = client
        .post(fixture.endpoint("/sized"))
        .version(HttpVersion::Http1_1)
        .body_stream_sized(
            CountingStream::new(&[b"abc", b"de"], sized_polls.clone()),
            5,
        )
        .send_streaming()
        .await
        .unwrap();
    assert_eq!(collect(response).await, b"ok");

    let requests = fixture.requests().await;
    let unknown = requests
        .iter()
        .find(|request| request.path == "/unknown")
        .unwrap();
    assert_eq!(
        header_value(&unknown.headers, "transfer-encoding"),
        Some("chunked")
    );
    assert_eq!(header_value(&unknown.headers, "content-length"), None);
    assert_eq!(unknown.raw_body, b"3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n");
    assert_eq!(unknown.decoded_body, b"abcde");
    assert!(
        unknown_polls.load(Ordering::SeqCst) >= 3,
        "producer should be polled incrementally through completion"
    );

    let sized = requests
        .iter()
        .find(|request| request.path == "/sized")
        .unwrap();
    assert_eq!(header_value(&sized.headers, "content-length"), Some("5"));
    assert_eq!(header_value(&sized.headers, "transfer-encoding"), None);
    assert_eq!(sized.raw_body, b"abcde");
    assert_eq!(sized.decoded_body, b"abcde");
    assert!(
        sized_polls.load(Ordering::SeqCst) >= 3,
        "sized producer should be polled through completion without pre-materialization"
    );
}

#[tokio::test]
async fn h1_stream_redirect_requiring_replay_fails_closed() {
    let fixture = H1UploadFixture::start().await;
    let client = Client::builder()
        .prefer_http2(false)
        .redirect_policy(RedirectPolicy::Limited(3))
        .build()
        .unwrap();

    let polls = Arc::new(AtomicUsize::new(0));
    let err = client
        .post(fixture.endpoint("/redirect"))
        .version(HttpVersion::Http1_1)
        .body_stream(CountingStream::new(&[b"abc"], polls.clone()))
        .send_streaming()
        .await
        .expect_err("streaming request redirects requiring replay must fail closed");

    let Error::HttpProtocol(message) = err else {
        panic!("expected clear HttpProtocol redirect error, got {err:?}");
    };
    assert!(
        message.contains("non-replayable streaming request body"),
        "unexpected redirect error message: {message}"
    );

    let requests = fixture.requests().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, "/redirect");
    assert!(
        polls.load(Ordering::SeqCst) >= 2,
        "the first request body may be sent, but it must never be replayed as empty"
    );
}
