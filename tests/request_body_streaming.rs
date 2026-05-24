//! Public request body streaming API surface coverage.
//!
//! VAL-API-003: `RequestBody::Stream { stream, content_length }` and the
//! `RequestBuilder::body_stream` / `body_stream_sized` builders accept
//! streaming producers without pre-buffering, while sized streams preserve
//! `Content-Length`. The duplicate `Body::Raw` request variant must no longer
//! exist on the public enum.
//!
//! VAL-API-004: `RequestBody::into_bytes` (and equivalent buffered helpers)
//! must reject streaming bodies with a clear error rather than silently
//! collecting them.

use bytes::Bytes;
use futures_core::Stream;
use specter::{Error, RequestBody};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

struct CountingStream {
    chunks: Vec<Bytes>,
    polls: Arc<AtomicUsize>,
    cursor: usize,
}

impl Stream for CountingStream {
    type Item = std::result::Result<Bytes, Error>;

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

#[test]
fn request_body_stream_public_api() {
    let polls = Arc::new(AtomicUsize::new(0));
    let stream = CountingStream {
        chunks: vec![Bytes::from_static(b"alpha-"), Bytes::from_static(b"omega")],
        polls: polls.clone(),
        cursor: 0,
    };

    let body = RequestBody::Stream {
        stream: Box::pin(stream),
        content_length: None,
    };
    assert!(body.is_streaming());
    assert!(body.content_length().is_none());
    assert_eq!(
        polls.load(Ordering::SeqCst),
        0,
        "constructing a streaming RequestBody must not poll the producer"
    );

    let polls_sized = Arc::new(AtomicUsize::new(0));
    let stream_sized = CountingStream {
        chunks: vec![Bytes::from_static(b"sized-bytes")],
        polls: polls_sized.clone(),
        cursor: 0,
    };
    let sized = RequestBody::Stream {
        stream: Box::pin(stream_sized),
        content_length: Some(11),
    };
    assert_eq!(sized.content_length(), Some(11));
    assert_eq!(
        polls_sized.load(Ordering::SeqCst),
        0,
        "sized stream constructor must not pre-buffer"
    );
}

#[test]
fn request_body_raw_variant_is_removed_from_public_enum() {
    let bytes_body = RequestBody::Bytes(Bytes::from_static(b"raw-replaces-bytes"));
    match bytes_body {
        RequestBody::Empty
        | RequestBody::Bytes(_)
        | RequestBody::Text(_)
        | RequestBody::Json(_)
        | RequestBody::Form(_)
        | RequestBody::Stream { .. } => {}
    }
    let from_slice: RequestBody = RequestBody::from(&b"slice"[..]);
    assert!(matches!(from_slice, RequestBody::Bytes(_)));
}

#[tokio::test]
async fn streaming_bodies_are_not_materialized_by_into_bytes() {
    let polls = Arc::new(AtomicUsize::new(0));
    let stream = CountingStream {
        chunks: vec![Bytes::from_static(b"refusing-to-materialize")],
        polls: polls.clone(),
        cursor: 0,
    };
    let body = RequestBody::Stream {
        stream: Box::pin(stream),
        content_length: None,
    };

    let err = body.into_bytes().expect_err(
        "streaming RequestBody::into_bytes must not silently buffer the producer to bytes",
    );
    match err {
        Error::HttpProtocol(msg) => assert!(
            msg.contains("streaming"),
            "error message must clearly identify the streaming-body refusal: {msg}"
        ),
        other => panic!("expected HttpProtocol error for streaming body, got {other:?}"),
    }
    assert_eq!(
        polls.load(Ordering::SeqCst),
        0,
        "into_bytes() must not poll the streaming producer when rejecting"
    );

    let buffered = RequestBody::Bytes(Bytes::from_static(b"buffered-ok"));
    assert_eq!(buffered.into_bytes().unwrap().as_ref(), b"buffered-ok");
}

#[test]
fn builder_body_stream_methods_do_not_pre_buffer_producer() {
    let client = specter::Client::new().expect("client");
    let polls = Arc::new(AtomicUsize::new(0));
    let stream = CountingStream {
        chunks: vec![Bytes::from_static(b"x"), Bytes::from_static(b"y")],
        polls: polls.clone(),
        cursor: 0,
    };
    let request = client
        .post("http://127.0.0.1:65535/")
        .body_stream(stream)
        .build()
        .expect("build streaming request");
    assert!(request.body().is_streaming());
    assert_eq!(request.body().content_length(), None);
    assert_eq!(
        polls.load(Ordering::SeqCst),
        0,
        "body_stream() must not poll the producer at request build time"
    );

    let sized_polls = Arc::new(AtomicUsize::new(0));
    let sized_stream = CountingStream {
        chunks: vec![Bytes::from_static(b"sized")],
        polls: sized_polls.clone(),
        cursor: 0,
    };
    let sized_request = client
        .post("http://127.0.0.1:65535/")
        .body_stream_sized(sized_stream, 5)
        .build()
        .expect("build sized streaming request");
    assert!(sized_request.body().is_streaming());
    assert_eq!(sized_request.body().content_length(), Some(5));
    assert_eq!(
        sized_polls.load(Ordering::SeqCst),
        0,
        "body_stream_sized() must not pre-buffer or poll the producer"
    );
}
