//! Poll-based HTTP/2 response body delivery.

use atomic_waker::AtomicWaker;
use bytes::{Bytes, BytesMut};
use http_body::{Body as HttpBody, Frame, SizeHint};
use std::cell::UnsafeCell;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::sync::Notify;
use tokio::time::{sleep, Instant, Sleep};

use crate::error::{Error, Result};
use crate::transport::connector::MaybeHttpsStream;
use crate::transport::h2::connection::{
    H2Connection as RawH2Connection, H2DirectPolledFrame, H2StreamData,
};
use crate::transport::h2::frame::FrameHeader;

/// Out-of-band HTTP/2 trailer block delivered from the driver: `(name, value)`
/// header pairs on success. Defined here (the lower-level body module) so both
/// the Body receiver side and the driver sender side share one definition.
pub(crate) type TrailerResult = Result<Vec<(String, String)>>;
/// Sender half of the conditional trailer side channel (held by the driver).
pub(crate) type TrailerSender = tokio::sync::oneshot::Sender<TrailerResult>;
/// Receiver half of the conditional trailer side channel (held by the Body).
pub(crate) type TrailerReceiver = tokio::sync::oneshot::Receiver<TrailerResult>;

#[derive(Clone, Copy, Debug, Default)]
pub struct H2BodyTimeouts {
    pub(crate) read_idle: Option<Duration>,
    pub(crate) total: Option<Duration>,
}

pub(crate) enum H2BodyPush {
    Accepted,
    Full(std::result::Result<Bytes, Error>),
    Closed,
}

pub(crate) enum H2BodyDataPush {
    Accepted { queued_len: usize },
    Full(Bytes),
    Closed,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct H2BodyCapacity {
    pub buffer_capacity: usize,
    pub buffered_chunks: usize,
    pub available_slots: usize,
    pub buffered_bytes: usize,
    pub closed: bool,
    pub ended: bool,
}

/// Default bounded in-flight DATA item capacity per H2 stream body.
///
/// H2 stream-level flow control still bounds total in-flight bytes; this cap
/// is a safety bound on the number of distinct chunks queued between the
/// driver and the consumer, which removes the per-chunk lock-step round-trip
/// the original single-slot design imposed.
///
/// Per-slot overhead is ~32 B (`Option<Result<Bytes, Error>>` in the SPSC ring).
/// Buffered payload is still bounded by the stream receive window (65535 with
/// stock SETTINGS, up to 6 MiB with the Chrome-fingerprint initial window).
pub const DEFAULT_H2_BODY_SLOT_CAPACITY: usize = 32;
/// Typical number of small DATA chunks coalesced into one consumer poll yield.
const H2_BODY_COALESCE_HINT: usize = 5;
const H2_BODY_CHUNK_COALESCE_LIMIT: usize = 16 * 1024;
const H2_DIRECT_DEFER_FLOW_BYTES: usize = 1024 * 1024;
const MIN_RELEASE_NOTIFY_BYTES: usize = 8 * 1024;
const MAX_RELEASE_NOTIFY_BYTES: usize = 512 * 1024;

type H2BodyItem = std::result::Result<Bytes, Error>;

/// Shared DATA slots between the H2 driver and the public `Body` poller.
///
/// Driver-owned wakeable state with a bounded ring of in-flight chunks plus
/// a consumer `Waker` and a `Notify` to wake the driver when the
/// consumer drains a chunk and the slot becomes refillable.
pub struct H2BodyShared {
    slots: Vec<UnsafeCell<Option<H2BodyItem>>>,
    head: AtomicUsize,
    tail: AtomicUsize,
    ended: AtomicBool,
    consumer_waker: AtomicWaker,
    closed: AtomicBool,
    released_recv_bytes: AtomicUsize,
    buffered_bytes: AtomicUsize,
    release_notify_bytes: usize,
    driver_notify: Arc<Notify>,
}

// H2BodyShared is an SPSC queue: the H2 driver is the only producer and the
// public Body poller is the only consumer. Slot access is coordinated by the
// atomic head/tail indexes below.
unsafe impl Sync for H2BodyShared {}

impl H2BodyShared {
    pub(crate) fn new_with_capacity(
        driver_notify: Arc<Notify>,
        initial_window_size: u32,
        capacity: usize,
    ) -> Arc<Self> {
        let capacity = capacity.max(1);
        let release_notify_bytes = ((initial_window_size as usize) / 4)
            .clamp(MIN_RELEASE_NOTIFY_BYTES, MAX_RELEASE_NOTIFY_BYTES);
        Arc::new(Self {
            slots: (0..capacity).map(|_| UnsafeCell::new(None)).collect(),
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            ended: AtomicBool::new(false),
            consumer_waker: AtomicWaker::new(),
            closed: AtomicBool::new(false),
            released_recv_bytes: AtomicUsize::new(0),
            buffered_bytes: AtomicUsize::new(0),
            release_notify_bytes,
            driver_notify,
        })
    }

    pub(crate) fn push(&self, item: std::result::Result<Bytes, Error>) -> H2BodyPush {
        self.push_result(item, false)
    }

    #[inline(always)]
    fn queued_len_from(&self, head: usize, tail: usize) -> usize {
        tail.saturating_sub(head)
    }

    #[inline(always)]
    fn slot_capacity(&self) -> usize {
        self.slots.len()
    }

    #[inline(always)]
    fn try_push_item(&self, item: H2BodyItem, end_stream: bool) -> H2BodyPush {
        if self.closed.load(Ordering::Acquire) {
            return H2BodyPush::Closed;
        }

        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire);
        let queued_len = self.queued_len_from(head, tail);
        let capacity = self.slot_capacity();
        if queued_len >= capacity {
            return H2BodyPush::Full(item);
        }

        let buffered_len = item.as_ref().ok().map(Bytes::len).unwrap_or(0);
        let wake_consumer = queued_len == 0 || end_stream;
        let slot = tail % capacity;
        // SAFETY: the producer is single-threaded, and queued_len < capacity
        // means the consumer has released this slot before advancing head.
        unsafe {
            *self.slots[slot].get() = Some(item);
        }
        if buffered_len > 0 {
            self.buffered_bytes
                .fetch_add(buffered_len, Ordering::Relaxed);
        }
        self.tail.store(tail + 1, Ordering::Release);
        if end_stream {
            self.ended.store(true, Ordering::Release);
        }
        if wake_consumer {
            self.consumer_waker.wake();
        }
        H2BodyPush::Accepted
    }

    #[inline(always)]
    fn pop_item(&self) -> Option<(H2BodyItem, bool)> {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        let queued_len = self.queued_len_from(head, tail);
        if queued_len == 0 {
            return None;
        }

        let capacity = self.slot_capacity();
        let slot = head % capacity;
        // SAFETY: the consumer is single-threaded, and tail > head means the
        // producer initialized this slot before publishing tail.
        let item = unsafe { (*self.slots[slot].get()).take() };
        self.head.store(head + 1, Ordering::Release);
        item.map(|item| {
            if let Ok(bytes) = &item {
                self.buffered_bytes
                    .fetch_sub(bytes.len(), Ordering::Relaxed);
            }
            (item, queued_len >= capacity)
        })
    }

    #[inline(always)]
    fn front_data_len(&self) -> Option<usize> {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        if self.queued_len_from(head, tail) == 0 {
            return None;
        }

        let slot = head % self.slot_capacity();
        // SAFETY: the consumer is the only reader of the front slot, and
        // tail > head means the producer has fully initialized it.
        unsafe {
            (*self.slots[slot].get())
                .as_ref()
                .and_then(|item| item.as_ref().ok().map(Bytes::len))
        }
    }

    #[inline(always)]
    fn has_data(&self) -> bool {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        self.queued_len_from(head, tail) > 0
    }

    #[inline(always)]
    fn has_data_or_end(&self) -> bool {
        self.has_data() || self.ended.load(Ordering::Acquire)
    }

    #[inline(always)]
    pub(crate) fn push_data(&self, data: Bytes, end_stream: bool) -> H2BodyDataPush {
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire);
        let queued_len = self.queued_len_from(head, tail);
        if self.closed.load(Ordering::Acquire) {
            return H2BodyDataPush::Closed;
        }
        let capacity = self.slot_capacity();
        if queued_len >= capacity {
            return H2BodyDataPush::Full(data);
        }

        let buffered_len = data.len();
        let wake_consumer = queued_len == 0 || end_stream;
        let slot = tail % capacity;
        // SAFETY: the producer is single-threaded, and queued_len < capacity
        // means this slot is not currently visible to the consumer.
        unsafe {
            *self.slots[slot].get() = Some(Ok(data));
        }
        if buffered_len > 0 {
            self.buffered_bytes
                .fetch_add(buffered_len, Ordering::Relaxed);
        }
        self.tail.store(tail + 1, Ordering::Release);
        if end_stream {
            self.ended.store(true, Ordering::Release);
        }
        if wake_consumer {
            self.consumer_waker.wake();
        }
        H2BodyDataPush::Accepted {
            queued_len: queued_len + 1,
        }
    }

    #[inline]
    fn push_result(&self, item: std::result::Result<Bytes, Error>, end_stream: bool) -> H2BodyPush {
        self.try_push_item(item, end_stream)
    }

    fn push_error(&self, error: Error) -> H2BodyPush {
        self.push(Err(error))
    }

    pub(crate) fn finish(&self) {
        self.ended.store(true, Ordering::Release);
        self.consumer_waker.wake();
    }

    pub(crate) fn fail(&self, error: Error) -> H2BodyPush {
        self.push_error(error)
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub(crate) fn is_slot_available(&self) -> bool {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        !self.closed.load(Ordering::Acquire)
            && self.queued_len_from(head, tail) < self.slot_capacity()
    }

    pub(crate) fn take_released_recv_bytes(&self) -> usize {
        self.released_recv_bytes.swap(0, Ordering::Relaxed)
    }

    pub(crate) fn capacity(&self) -> H2BodyCapacity {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        let buffered_chunks = self.queued_len_from(head, tail);
        let buffer_capacity = self.slot_capacity();
        H2BodyCapacity {
            buffer_capacity,
            buffered_chunks,
            available_slots: buffer_capacity.saturating_sub(buffered_chunks),
            buffered_bytes: self.buffered_bytes.load(Ordering::Relaxed),
            closed: self.closed.load(Ordering::Acquire),
            ended: self.ended.load(Ordering::Acquire),
        }
    }

    fn close(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.consumer_waker.wake();
            self.driver_notify.notify_one();
        }
    }
}

/// HTTP/2 response body backed by driver-owned wakeable state.
pub(crate) struct H2Body {
    shared: Arc<H2BodyShared>,
    read_idle_timeout: Option<Duration>,
    read_idle_sleep: Option<Pin<Box<Sleep>>>,
    total_timeout: Option<Duration>,
    total_sleep: Option<Pin<Box<Sleep>>>,
    terminal: bool,
    pending_release_bytes: usize,
    /// Side-channel receiver for HTTP/2 response trailers. `Some` only when the
    /// caller requested trailers (`te: trailers`). Consumed on first `trailers()`
    /// await. Never an item in the SPSC ring; off the DATA hot path entirely.
    trailers_rx: Option<TrailerReceiver>,
}

impl H2Body {
    pub(crate) fn new_with_trailers(
        shared: Arc<H2BodyShared>,
        timeouts: H2BodyTimeouts,
        trailers_rx: Option<TrailerReceiver>,
    ) -> Self {
        Self {
            shared,
            read_idle_timeout: timeouts.read_idle,
            read_idle_sleep: timeouts.read_idle.map(|duration| Box::pin(sleep(duration))),
            total_timeout: timeouts.total,
            total_sleep: timeouts.total.map(|duration| Box::pin(sleep(duration))),
            terminal: false,
            pending_release_bytes: 0,
            trailers_rx,
        }
    }

    /// Await the HTTP/2 response trailers for this stream, if any.
    ///
    /// Three-state contract (see the gRPC trailer-surfacing design):
    /// - receiver is `None` (trailers never requested) -> `Ok(None)`
    /// - `Err(RecvError)` (sender dropped = clean trailer-less end) -> `Ok(None)`
    /// - `Ok(Err(e))` (driver sent a reset error) -> `Err(e)`
    /// - `Ok(Ok(headers))` (real trailer frame) -> `Ok(Some(Headers))`
    ///
    /// The receiver is consumed on the first await; a second call yields
    /// `Ok(None)`. Await only after the body stream has returned end: a
    /// resolved trailer channel does not imply the body has been drained.
    pub(crate) async fn trailers(&mut self) -> Result<Option<crate::headers::Headers>> {
        let Some(rx) = self.trailers_rx.take() else {
            return Ok(None);
        };
        match rx.await {
            Err(_) => Ok(None),
            Ok(Err(e)) => Err(e),
            Ok(Ok(headers)) => Ok(Some(crate::headers::Headers::from(headers))),
        }
    }

    pub(crate) fn take_trailers_rx(&mut self) -> Option<TrailerReceiver> {
        self.trailers_rx.take()
    }

    pub(crate) fn is_terminal(&self) -> bool {
        self.terminal
    }

    pub(crate) fn capacity(&self) -> H2BodyCapacity {
        self.shared.capacity()
    }

    #[inline]
    fn reset_read_idle(&mut self) {
        if let Some(duration) = self.read_idle_timeout {
            self.read_idle_sleep = Some(Box::pin(sleep(duration)));
        }
    }

    #[inline]
    fn timeouts_enabled(&self) -> bool {
        self.total_sleep.is_some() || self.read_idle_timeout.is_some()
    }

    #[inline(always)]
    fn release_recv_bytes(&mut self, released: usize, notify_slot_available: bool) {
        self.pending_release_bytes += released;
        if notify_slot_available || self.pending_release_bytes >= self.shared.release_notify_bytes {
            let released = std::mem::take(&mut self.pending_release_bytes);
            if released > 0 {
                self.shared
                    .released_recv_bytes
                    .fetch_add(released, Ordering::Relaxed);
            }
            self.shared.driver_notify.notify_one();
        }
    }

    #[inline(always)]
    pub(crate) fn poll_data(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Bytes, Error>>> {
        if self.terminal {
            return Poll::Ready(None);
        }

        loop {
            if let Some((item, was_full)) = self.shared.pop_item() {
                let notify_slot_available = was_full && !self.shared.ended.load(Ordering::Acquire);
                match item {
                    Ok(bytes) => {
                        let released = bytes.len();
                        self.release_recv_bytes(released, notify_slot_available);
                        self.reset_read_idle();
                        if bytes.is_empty() {
                            continue;
                        }
                        return Poll::Ready(Some(Ok(bytes)));
                    }
                    Err(error) => {
                        self.terminal = true;
                        self.shared.close();
                        return Poll::Ready(Some(Err(error)));
                    }
                }
            }

            if self.shared.ended.load(Ordering::Acquire) {
                if self.shared.has_data() {
                    continue;
                }
                self.terminal = true;
                self.shared.closed.store(true, Ordering::Release);
                return Poll::Ready(None);
            }

            self.shared.consumer_waker.register(cx.waker());
            if self.shared.has_data_or_end() {
                continue;
            }
            break;
        }

        if self.timeouts_enabled() {
            if let Some(total_sleep) = self.total_sleep.as_mut() {
                if total_sleep.as_mut().poll(cx).is_ready() {
                    self.terminal = true;
                    self.shared.close();
                    let duration = self.total_timeout.expect("total sleep without duration");
                    return Poll::Ready(Some(Err(Error::TotalTimeout(duration))));
                }
            }

            if let Some(read_idle_sleep) = self.read_idle_sleep.as_mut() {
                if read_idle_sleep.as_mut().poll(cx).is_ready() {
                    self.terminal = true;
                    self.shared.close();
                    let duration = self
                        .read_idle_timeout
                        .expect("read-idle sleep without duration");
                    return Poll::Ready(Some(Err(Error::ReadIdleTimeout(duration))));
                }
            }
        }

        Poll::Pending
    }

    #[inline(always)]
    pub(crate) fn poll_data_coalesced(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Bytes, Error>>> {
        if self.terminal {
            return Poll::Ready(None);
        }

        loop {
            if let Some((item, was_full)) = self.shared.pop_item() {
                match item {
                    Ok(first) => {
                        let mut released = first.len();
                        let mut total_len = first.len();
                        let mut extra: Option<Vec<Bytes>> = None;
                        let mut notify_slot_available =
                            was_full && !self.shared.ended.load(Ordering::Acquire);

                        if first.len() < H2_BODY_CHUNK_COALESCE_LIMIT {
                            while let Some(front_len) = self.shared.front_data_len() {
                                if front_len > 0
                                    && total_len + front_len > H2_BODY_CHUNK_COALESCE_LIMIT
                                {
                                    break;
                                }
                                let Some((next_item, next_was_full)) = self.shared.pop_item()
                                else {
                                    break;
                                };
                                let Ok(bytes) = next_item else {
                                    break;
                                };
                                notify_slot_available |=
                                    next_was_full && !self.shared.ended.load(Ordering::Acquire);
                                released += bytes.len();
                                if bytes.is_empty() {
                                    continue;
                                }
                                total_len += bytes.len();
                                extra
                                    .get_or_insert_with(|| {
                                        Vec::with_capacity(H2_BODY_COALESCE_HINT)
                                    })
                                    .push(bytes);
                            }
                        }

                        self.release_recv_bytes(released, notify_slot_available);
                        self.reset_read_idle();

                        match extra {
                            Some(extra) => {
                                let mut combined = BytesMut::with_capacity(total_len);
                                combined.extend_from_slice(&first);
                                for chunk in extra {
                                    combined.extend_from_slice(&chunk);
                                }
                                return Poll::Ready(Some(Ok(combined.freeze())));
                            }
                            None if first.is_empty() => continue,
                            None => return Poll::Ready(Some(Ok(first))),
                        }
                    }
                    Err(error) => {
                        self.terminal = true;
                        self.shared.close();
                        return Poll::Ready(Some(Err(error)));
                    }
                }
            }

            if self.shared.ended.load(Ordering::Acquire) {
                if self.shared.has_data() {
                    continue;
                }
                self.terminal = true;
                self.shared.closed.store(true, Ordering::Release);
                return Poll::Ready(None);
            }

            self.shared.consumer_waker.register(cx.waker());
            if self.shared.has_data_or_end() {
                continue;
            }
            break;
        }

        if self.timeouts_enabled() {
            if let Some(total_sleep) = self.total_sleep.as_mut() {
                if total_sleep.as_mut().poll(cx).is_ready() {
                    self.terminal = true;
                    self.shared.close();
                    let duration = self.total_timeout.expect("total sleep without duration");
                    return Poll::Ready(Some(Err(Error::TotalTimeout(duration))));
                }
            }

            if let Some(read_idle_sleep) = self.read_idle_sleep.as_mut() {
                if read_idle_sleep.as_mut().poll(cx).is_ready() {
                    self.terminal = true;
                    self.shared.close();
                    let duration = self
                        .read_idle_timeout
                        .expect("read-idle sleep without duration");
                    return Poll::Ready(Some(Err(Error::ReadIdleTimeout(duration))));
                }
            }
        }

        Poll::Pending
    }
}

impl Drop for H2Body {
    fn drop(&mut self) {
        if !self.terminal {
            self.shared.close();
        }
    }
}

impl HttpBody for H2Body {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
        match self.poll_data(cx) {
            Poll::Ready(Some(Ok(bytes))) => Poll::Ready(Some(Ok(Frame::data(bytes)))),
            Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(error))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.terminal
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;

    #[test]
    fn h2_body_shared_uses_configured_slot_capacity() {
        let shared = H2BodyShared::new_with_capacity(Arc::new(Notify::new()), 65_535, 2);

        assert!(matches!(
            shared.push_data(Bytes::from_static(b"one"), false),
            H2BodyDataPush::Accepted { queued_len: 1 }
        ));
        assert!(matches!(
            shared.push_data(Bytes::from_static(b"two"), false),
            H2BodyDataPush::Accepted { queued_len: 2 }
        ));
        assert!(matches!(
            shared.push_data(Bytes::from_static(b"three"), false),
            H2BodyDataPush::Full(_)
        ));
    }

    #[test]
    fn h2_body_capacity_snapshot_reports_buffer_pressure() {
        let shared = H2BodyShared::new_with_capacity(Arc::new(Notify::new()), 65_535, 3);
        assert!(matches!(
            shared.push_data(Bytes::from_static(b"one"), false),
            H2BodyDataPush::Accepted { queued_len: 1 }
        ));
        assert!(matches!(
            shared.push_data(Bytes::from_static(b"two-two"), false),
            H2BodyDataPush::Accepted { queued_len: 2 }
        ));

        let capacity = shared.capacity();

        assert_eq!(capacity.buffer_capacity, 3);
        assert_eq!(capacity.buffered_chunks, 2);
        assert_eq!(capacity.available_slots, 1);
        assert_eq!(capacity.buffered_bytes, 10);
        assert!(!capacity.closed);
        assert!(!capacity.ended);
    }

    fn test_body(trailers_rx: Option<TrailerReceiver>) -> H2Body {
        let shared = H2BodyShared::new_with_capacity(Arc::new(Notify::new()), 65_535, 2);
        H2Body::new_with_trailers(shared, H2BodyTimeouts::default(), trailers_rx)
    }

    // Structural no-alloc backstop: a body built without a trailer receiver
    // (the non-`te: trailers` warm path) resolves trailers to `Ok(None)` and
    // never awaits a channel. Neither handle.rs construction site allocates a
    // trailer `oneshot::channel()` unless `wants_trailers` is true.
    #[tokio::test]
    async fn trailers_none_receiver_yields_ok_none() {
        let mut body = test_body(None);
        assert!(body.trailers().await.unwrap().is_none());
        // Idempotent: a second call also yields Ok(None).
        assert!(body.trailers().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn trailers_dropped_sender_yields_ok_none() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let mut body = test_body(Some(rx));
        drop(tx); // clean trailer-less end
        assert!(body.trailers().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn trailers_reset_error_yields_err() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let mut body = test_body(Some(rx));
        tx.send(Err(Error::HttpProtocol("stream reset".into())))
            .unwrap();
        assert!(body.trailers().await.is_err());
    }

    #[tokio::test]
    async fn trailers_real_frame_yields_some_headers() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let mut body = test_body(Some(rx));
        tx.send(Ok(vec![("grpc-status".to_string(), "0".to_string())]))
            .unwrap();
        let trailers = body.trailers().await.unwrap().unwrap();
        assert_eq!(trailers.get("grpc-status"), Some("0"));
        // Consumed on first await.
        assert!(body.trailers().await.unwrap().is_none());
    }
}

pub(crate) type H2DirectReuseHook = Box<dyn FnOnce(RawH2Connection<MaybeHttpsStream>) + Send>;

type H2DirectReadFuture =
    Pin<Box<dyn Future<Output = (RawH2Connection<MaybeHttpsStream>, Result<H2StreamData>)> + Send>>;

/// HTTP/2 response body that owns the raw connection until EOF.
///
/// This path is used only for ordinary single-stream, empty-request-body
/// downloads when no multiplexed driver connection is already active. It lets
/// the caller task poll DATA frames directly, avoiding the background
/// driver-to-body queue handoff on the H2 download hot path.
pub(crate) struct H2DirectBody {
    conn: Option<RawH2Connection<MaybeHttpsStream>>,
    read_future: Option<H2DirectReadFuture>,
    stream_id: u32,
    conn_recv_window: i32,
    recv_window: i32,
    deferred_recv_bytes: usize,
    terminal: bool,
    end_after_current_chunk: bool,
    on_reusable: Option<H2DirectReuseHook>,
    read_idle_timeout: Option<Duration>,
    read_idle_sleep: Option<Pin<Box<Sleep>>>,
    total_timeout: Option<Duration>,
    total_sleep: Option<Pin<Box<Sleep>>>,
}

impl H2DirectBody {
    pub(crate) fn new(
        conn: RawH2Connection<MaybeHttpsStream>,
        stream_id: u32,
        timeouts: H2BodyTimeouts,
        on_reusable: H2DirectReuseHook,
    ) -> Self {
        let conn_recv_window = conn.connection_recv_window();
        let recv_window = conn.local_initial_window_size() as i32;
        Self {
            conn: Some(conn),
            read_future: None,
            stream_id,
            conn_recv_window,
            recv_window,
            deferred_recv_bytes: 0,
            terminal: false,
            end_after_current_chunk: false,
            on_reusable: Some(on_reusable),
            read_idle_timeout: timeouts.read_idle,
            read_idle_sleep: None,
            total_timeout: timeouts.total,
            total_sleep: timeouts.total.map(|duration| Box::pin(sleep(duration))),
        }
    }

    pub(crate) fn is_terminal(&self) -> bool {
        self.terminal
    }

    fn reset_read_idle(&mut self) {
        self.read_idle_sleep = None;
    }

    #[inline]
    fn timeouts_enabled(&self) -> bool {
        self.total_sleep.is_some() || self.read_idle_timeout.is_some()
    }

    fn poll_timeouts(&mut self, cx: &mut Context<'_>) -> Option<Error> {
        if let Some(total) = self.total_sleep.as_mut() {
            if total.as_mut().poll(cx).is_ready() {
                return Some(Error::TotalTimeout(self.total_timeout.unwrap_or_else(
                    || total.deadline().saturating_duration_since(Instant::now()),
                )));
            }
        }

        if let Some(read_idle) = self.read_idle_timeout {
            let sleep = self
                .read_idle_sleep
                .get_or_insert_with(|| Box::pin(tokio::time::sleep(read_idle)));
            if sleep.as_mut().poll(cx).is_ready() {
                return Some(Error::ReadIdleTimeout(read_idle));
            }
        }

        None
    }

    fn release_to_pool(&mut self) {
        if let Some(conn) = self.conn.take() {
            let mut conn = conn;
            if self.deferred_recv_bytes > 0 {
                let deferred = self.deferred_recv_bytes as i32;
                self.conn_recv_window = self.conn_recv_window.saturating_sub(deferred);
                self.recv_window = self.recv_window.saturating_sub(deferred);
                self.deferred_recv_bytes = 0;
            }
            conn.remove_stream(self.stream_id);
            conn.set_connection_recv_window(self.conn_recv_window);
            conn.set_stream_recv_window(self.stream_id, self.recv_window);
            if conn.is_reusable()
                && self.conn_recv_window >= conn.connection_flow_control_refresh_threshold()
                && self.recv_window >= conn.flow_control_refresh_threshold()
            {
                if let Some(on_reusable) = self.on_reusable.take() {
                    on_reusable(conn);
                }
            }
        }
        self.read_future = None;
        self.on_reusable = None;
        self.terminal = true;
    }

    fn return_to_pool(&mut self) -> Poll<Option<std::result::Result<Bytes, Error>>> {
        self.release_to_pool();
        Poll::Ready(None)
    }

    fn fail(&mut self, error: Error) -> Poll<Option<std::result::Result<Bytes, Error>>> {
        self.conn = None;
        self.read_future = None;
        self.on_reusable = None;
        self.terminal = true;
        Poll::Ready(Some(Err(error)))
    }

    #[inline(always)]
    fn poll_data_without_timeouts(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Bytes, Error>>> {
        loop {
            let polled_frame = {
                let Some(conn) = self.conn.as_mut() else {
                    return self.fail(Error::HttpProtocol(
                        "H2 direct response body connection is no longer available".into(),
                    ));
                };

                match conn.poll_read_direct_frame(cx, self.stream_id) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(frame)) => frame,
                    Poll::Ready(Err(error)) => return self.fail(error),
                }
            };

            if let H2DirectPolledFrame::Data { bytes, end_stream } = polled_frame {
                let data_len = bytes.len();
                if end_stream {
                    self.deferred_recv_bytes += data_len;
                    if data_len == 0 {
                        return self.return_to_pool();
                    }
                    self.end_after_current_chunk = true;
                    return Poll::Ready(Some(Ok(bytes)));
                }

                let deferred_recv_bytes = self.deferred_recv_bytes + data_len;
                if deferred_recv_bytes <= H2_DIRECT_DEFER_FLOW_BYTES {
                    self.deferred_recv_bytes = deferred_recv_bytes;
                    if data_len == 0 {
                        continue;
                    }
                    return Poll::Ready(Some(Ok(bytes)));
                }

                return self.poll_deferred_flow_update(cx, bytes, false);
            }

            return self.poll_direct_fallback(cx, polled_frame);
        }
    }

    #[cold]
    fn poll_deferred_flow_update(
        &mut self,
        cx: &mut Context<'_>,
        bytes: Bytes,
        end_stream: bool,
    ) -> Poll<Option<std::result::Result<Bytes, Error>>> {
        let data_len = bytes.len();
        let Some(conn) = self.conn.as_mut() else {
            return self.fail(Error::HttpProtocol(
                "H2 direct response body connection is no longer available".into(),
            ));
        };

        if self.deferred_recv_bytes > 0 {
            let deferred = self.deferred_recv_bytes as i32;
            self.conn_recv_window = self.conn_recv_window.saturating_sub(deferred);
            self.recv_window = self.recv_window.saturating_sub(deferred);
            self.deferred_recv_bytes = 0;
        }
        self.conn_recv_window -= data_len as i32;
        let conn_increment =
            if self.conn_recv_window < conn.connection_flow_control_refresh_threshold() {
                let increment = conn.connection_flow_control_refresh_increment();
                self.conn_recv_window = self.conn_recv_window.saturating_add(increment as i32);
                Some(increment)
            } else {
                None
            };
        if data_len > 0 {
            self.recv_window -= data_len as i32;
        }
        let stream_increment = if self.recv_window < conn.flow_control_refresh_threshold() {
            let increment = conn.flow_control_refresh_increment();
            self.recv_window = self.recv_window.saturating_add(increment as i32);
            Some(increment)
        } else {
            None
        };

        if conn_increment.is_none() && stream_increment.is_none() {
            if self.read_idle_timeout.is_some() {
                self.reset_read_idle();
            }
            if data_len == 0 {
                if end_stream {
                    return self.return_to_pool();
                }
                return self.poll_data_slow(cx);
            }
            return Poll::Ready(Some(Ok(bytes)));
        }

        let Some(mut conn) = self.conn.take() else {
            return self.fail(Error::HttpProtocol(
                "H2 direct response body connection is no longer available".into(),
            ));
        };
        let stream_id = self.stream_id;
        self.read_future = Some(Box::pin(async move {
            let result = async {
                conn.send_inbound_window_updates(stream_id, conn_increment, stream_increment)
                    .await?;
                Ok(H2StreamData::Data { bytes, end_stream })
            }
            .await;
            (conn, result)
        }));
        self.poll_data_slow(cx)
    }

    #[cold]
    fn poll_direct_fallback(
        &mut self,
        cx: &mut Context<'_>,
        polled_frame: H2DirectPolledFrame,
    ) -> Poll<Option<std::result::Result<Bytes, Error>>> {
        let Some(mut conn) = self.conn.take() else {
            return self.fail(Error::HttpProtocol(
                "H2 direct response body connection is no longer available".into(),
            ));
        };
        let stream_id = self.stream_id;
        conn.set_connection_recv_window(self.conn_recv_window);
        conn.set_stream_recv_window(stream_id, self.recv_window);
        let first_frame: Option<(FrameHeader, Bytes)> = match polled_frame {
            H2DirectPolledFrame::Other(header, payload) => Some((header, payload)),
            H2DirectPolledFrame::Data { .. } => unreachable!(),
        };
        self.read_future = Some(Box::pin(async move {
            let result = conn
                .read_stream_data_direct_from(stream_id, first_frame)
                .await;
            (conn, result)
        }));
        self.poll_data_slow(cx)
    }

    #[cold]
    fn poll_data_slow(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Bytes, Error>>> {
        if self.timeouts_enabled() {
            if let Some(error) = self.poll_timeouts(cx) {
                return self.fail(error);
            }
        }

        loop {
            if let Some(future) = self.read_future.as_mut() {
                match future.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready((conn, Ok(H2StreamData::Data { bytes, end_stream }))) => {
                        self.conn = Some(conn);
                        self.read_future = None;
                        if self.read_idle_timeout.is_some() {
                            self.reset_read_idle();
                        }
                        if bytes.is_empty() {
                            if end_stream {
                                return self.return_to_pool();
                            }
                            continue;
                        }
                        if end_stream {
                            self.end_after_current_chunk = true;
                        }
                        return Poll::Ready(Some(Ok(bytes)));
                    }
                    Poll::Ready((conn, Ok(H2StreamData::End))) => {
                        self.conn = Some(conn);
                        self.read_future = None;
                        return self.return_to_pool();
                    }
                    Poll::Ready((_conn, Err(error))) => {
                        self.read_future = None;
                        return self.fail(error);
                    }
                }
            }

            let polled_frame = {
                let Some(conn) = self.conn.as_mut() else {
                    return self.fail(Error::HttpProtocol(
                        "H2 direct response body connection is no longer available".into(),
                    ));
                };

                match conn.poll_read_direct_frame(cx, self.stream_id) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(frame)) => frame,
                    Poll::Ready(Err(error)) => return self.fail(error),
                }
            };

            if let H2DirectPolledFrame::Data { bytes, end_stream } = polled_frame {
                let data_len = bytes.len();
                if end_stream {
                    self.deferred_recv_bytes += data_len;
                    if bytes.is_empty() {
                        return self.return_to_pool();
                    }
                    self.end_after_current_chunk = true;
                    return Poll::Ready(Some(Ok(bytes)));
                }

                let deferred_recv_bytes = self.deferred_recv_bytes + data_len;
                if deferred_recv_bytes <= H2_DIRECT_DEFER_FLOW_BYTES {
                    self.deferred_recv_bytes = deferred_recv_bytes;
                    if self.read_idle_timeout.is_some() {
                        self.reset_read_idle();
                    }
                    if bytes.is_empty() {
                        continue;
                    }
                    return Poll::Ready(Some(Ok(bytes)));
                }

                return self.poll_deferred_flow_update(cx, bytes, end_stream);
            }

            return self.poll_direct_fallback(cx, polled_frame);
        }
    }

    #[inline(always)]
    pub(crate) fn poll_data(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Bytes, Error>>> {
        let this = &mut *self;
        if this.terminal {
            return Poll::Ready(None);
        }

        if this.end_after_current_chunk {
            return this.return_to_pool();
        }

        if this.read_future.is_none() && !this.timeouts_enabled() {
            return this.poll_data_without_timeouts(cx);
        }

        this.poll_data_slow(cx)
    }
}

impl Drop for H2DirectBody {
    fn drop(&mut self) {
        if !self.terminal && self.end_after_current_chunk {
            let _ = self.return_to_pool();
        }
    }
}

impl HttpBody for H2DirectBody {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
        match self.poll_data(cx) {
            Poll::Ready(Some(Ok(bytes))) => Poll::Ready(Some(Ok(Frame::data(bytes)))),
            Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(error))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.terminal
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}
