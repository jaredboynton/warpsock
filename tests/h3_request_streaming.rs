use bytes::Bytes;
use futures_core::Stream;
use specter::{Client, Error, HttpVersion};
use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

mod helpers;
use helpers::mock_h3_server::{MockEvent, MockH3Server};

struct CountingBodyStream {
    chunks: VecDeque<Bytes>,
    polls: Arc<AtomicUsize>,
}

impl CountingBodyStream {
    fn new(chunks: impl IntoIterator<Item = Bytes>, polls: Arc<AtomicUsize>) -> Self {
        Self {
            chunks: chunks.into_iter().collect(),
            polls,
        }
    }
}

impl Stream for CountingBodyStream {
    type Item = Result<Bytes, Error>;

    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(self.chunks.pop_front().map(Ok))
    }
}

#[tokio::test]
async fn h3_request_stream_body_flow_control_and_fin() {
    let server = MockH3Server::new().await.unwrap();
    let url = server.url();

    server.start(|conn| async move {
        let mut stream_id = None;
        let mut received = Vec::new();

        loop {
            match conn.read_event().await {
                Some(MockEvent::Headers {
                    stream_id: id,
                    headers,
                }) => {
                    stream_id = Some(id);
                    let content_length = headers
                        .iter()
                        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                        .map(|(_, value)| value.as_str());
                    assert_eq!(content_length, Some("11"));
                }
                Some(MockEvent::Data { data, .. }) => {
                    received.extend_from_slice(&data);
                }
                Some(MockEvent::Finished { stream_id: id }) => {
                    assert_eq!(stream_id, Some(id));
                    assert_eq!(received, b"hello world");
                    conn.send_response_headers(id, vec![(":status", "200")], false)
                        .await;
                    conn.send_response_data(id, b"uploaded", true).await;
                    return;
                }
                Some(_) => {}
                None => return,
            }
        }
    });

    let polls = Arc::new(AtomicUsize::new(0));
    let body = CountingBodyStream::new(
        [
            Bytes::from_static(b"hello"),
            Bytes::from_static(b" "),
            Bytes::from_static(b"world"),
        ],
        polls.clone(),
    );

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let mut response = client
        .post(&url)
        .version(HttpVersion::Http3Only)
        .body_stream_sized(body, 11)
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
    assert_eq!(chunk, Bytes::from_static(b"uploaded"));
    assert!(response.body_mut().frame().await.is_none());

    // Three chunks plus one terminal poll. A materially larger value would
    // indicate eager producer polling beyond transport progress.
    assert_eq!(polls.load(Ordering::SeqCst), 4);
}
