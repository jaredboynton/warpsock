//! Poll-based HTTP/2 response body delivery.

use atomic_waker::AtomicWaker;
use bytes::Bytes;
use http_body::{Body as HttpBody, Frame, SizeHint};
use parking_lot::Mutex;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::sync::Notify;
use tokio::time::{sleep, Sleep};

use crate::error::Error;

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

/// Bounded in-flight DATA item capacity per H2 stream body.
///
/// H2 stream-level flow control still bounds total in-flight bytes; this cap
/// is a safety bound on the number of distinct chunks queued between the
/// driver and the consumer, which removes the per-chunk lock-step round-trip
/// the original single-slot design imposed.
const H2_BODY_SLOT_CAPACITY: usize = 3;
const MIN_RELEASE_NOTIFY_BYTES: usize = 8 * 1024;
const MAX_RELEASE_NOTIFY_BYTES: usize = 512 * 1024;

struct H2BodyState {
    slots: [Option<std::result::Result<Bytes, Error>>; H2_BODY_SLOT_CAPACITY],
    head: usize,
    len: usize,
    terminal_error: Option<Error>,
    ended: bool,
    closed: bool,
}

impl Default for H2BodyState {
    fn default() -> Self {
        Self {
            slots: std::array::from_fn(|_| None),
            head: 0,
            len: 0,
            terminal_error: None,
            ended: false,
            closed: false,
        }
    }
}

impl H2BodyState {
    #[inline]
    fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    fn is_full(&self) -> bool {
        self.len == H2_BODY_SLOT_CAPACITY
    }

    #[inline]
    fn push_back(&mut self, item: std::result::Result<Bytes, Error>) {
        debug_assert!(!self.is_full());
        let tail = (self.head + self.len) % H2_BODY_SLOT_CAPACITY;
        self.slots[tail] = Some(item);
        self.len += 1;
    }

    #[inline]
    fn pop_front(&mut self) -> Option<std::result::Result<Bytes, Error>> {
        if self.is_empty() {
            return None;
        }
        let item = self.slots[self.head].take();
        self.head = (self.head + 1) % H2_BODY_SLOT_CAPACITY;
        self.len -= 1;
        item
    }
}

/// Shared DATA slots between the H2 driver and the public `Body` poller.
///
/// Driver-owned wakeable state with a bounded ring of in-flight chunks plus
/// a consumer `Waker` and a `Notify` to wake the driver when the
/// consumer drains a chunk and the slot becomes refillable.
pub struct H2BodyShared {
    state: Mutex<H2BodyState>,
    consumer_waker: AtomicWaker,
    closed: AtomicBool,
    released_recv_bytes: AtomicUsize,
    release_notify_bytes: usize,
    driver_notify: Arc<Notify>,
}

impl H2BodyShared {
    pub(crate) fn new(driver_notify: Arc<Notify>, initial_window_size: u32) -> Arc<Self> {
        let release_notify_bytes = ((initial_window_size as usize) / 4)
            .clamp(MIN_RELEASE_NOTIFY_BYTES, MAX_RELEASE_NOTIFY_BYTES);
        Arc::new(Self {
            state: Mutex::new(H2BodyState::default()),
            consumer_waker: AtomicWaker::new(),
            closed: AtomicBool::new(false),
            released_recv_bytes: AtomicUsize::new(0),
            release_notify_bytes,
            driver_notify,
        })
    }

    pub(crate) fn push(&self, item: std::result::Result<Bytes, Error>) -> H2BodyPush {
        self.push_result(item, false)
    }

    pub(crate) fn push_data(&self, data: Bytes, end_stream: bool) -> H2BodyDataPush {
        let (wake_consumer, queued_len) = {
            let mut state = self.state.lock();
            if state.closed {
                return H2BodyDataPush::Closed;
            }
            if state.is_full() {
                return H2BodyDataPush::Full(data);
            }
            let wake_consumer = state.is_empty() || end_stream;
            state.push_back(Ok(data));
            if end_stream {
                state.ended = true;
            }
            (wake_consumer, state.len)
        };
        if wake_consumer {
            self.consumer_waker.wake();
        }
        H2BodyDataPush::Accepted { queued_len }
    }

    fn push_result(&self, item: std::result::Result<Bytes, Error>, end_stream: bool) -> H2BodyPush {
        let wake_consumer = {
            let mut state = self.state.lock();
            if state.closed {
                return H2BodyPush::Closed;
            }
            if state.is_full() {
                return H2BodyPush::Full(item);
            }
            let wake_consumer = state.is_empty() || end_stream;
            state.push_back(item);
            if end_stream {
                state.ended = true;
            }
            wake_consumer
        };
        if wake_consumer {
            self.consumer_waker.wake();
        }
        H2BodyPush::Accepted
    }

    fn push_error(&self, error: Error) -> H2BodyPush {
        self.push(Err(error))
    }

    pub(crate) fn finish(&self) {
        let wake_consumer = {
            let mut state = self.state.lock();
            state.ended = true;
            state.is_empty()
        };
        if wake_consumer {
            self.consumer_waker.wake();
        }
    }

    pub(crate) fn fail(&self, error: Error) -> H2BodyPush {
        self.push_error(error)
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub(crate) fn is_slot_available(&self) -> bool {
        let state = self.state.lock();
        !state.closed && !state.is_full()
    }

    pub(crate) fn take_released_recv_bytes(&self) -> usize {
        self.released_recv_bytes.swap(0, Ordering::Relaxed)
    }

    fn close(&self) {
        let wake_consumer = {
            let mut state = self.state.lock();
            if !state.closed {
                state.closed = true;
                self.closed.store(true, Ordering::Release);
                true
            } else {
                false
            }
        };
        if wake_consumer {
            self.consumer_waker.wake();
        }
        self.driver_notify.notify_one();
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
}

impl H2Body {
    pub(crate) fn new(shared: Arc<H2BodyShared>, timeouts: H2BodyTimeouts) -> Self {
        Self {
            shared,
            read_idle_timeout: timeouts.read_idle,
            read_idle_sleep: timeouts.read_idle.map(|duration| Box::pin(sleep(duration))),
            total_timeout: timeouts.total,
            total_sleep: timeouts.total.map(|duration| Box::pin(sleep(duration))),
            terminal: false,
            pending_release_bytes: 0,
        }
    }

    pub(crate) fn is_terminal(&self) -> bool {
        self.terminal
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

    #[inline]
    fn release_recv_bytes(&mut self, released: usize, notify_slot_available: bool) {
        self.pending_release_bytes = self.pending_release_bytes.saturating_add(released);
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

    fn close_with_error(
        &mut self,
        error: Error,
    ) -> Poll<Option<std::result::Result<Frame<Bytes>, Error>>> {
        self.terminal = true;
        self.shared.close();
        Poll::Ready(Some(Err(error)))
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
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
        if self.terminal {
            return Poll::Ready(None);
        }

        enum StatePoll {
            Item {
                item: std::result::Result<Bytes, Error>,
                notify_slot_available: bool,
            },
            Error(Error),
            End,
            Pending,
        }

        let poll_state = |shared: &H2BodyShared| {
            let mut state = shared.state.lock();
            let was_full = state.is_full();
            if let Some(item) = state.pop_front() {
                StatePoll::Item {
                    item,
                    notify_slot_available: was_full,
                }
            } else if let Some(error) = state.terminal_error.take() {
                state.closed = true;
                StatePoll::Error(error)
            } else if state.ended {
                state.closed = true;
                StatePoll::End
            } else {
                StatePoll::Pending
            }
        };

        let mut state_poll = poll_state(&self.shared);
        if matches!(state_poll, StatePoll::Pending) {
            self.shared.consumer_waker.register(cx.waker());
            state_poll = poll_state(&self.shared);
        }

        match state_poll {
            StatePoll::Error(error) => {
                self.terminal = true;
                return Poll::Ready(Some(Err(error)));
            }
            StatePoll::End => {
                self.terminal = true;
                return Poll::Ready(None);
            }
            StatePoll::Pending => {}
            StatePoll::Item {
                item,
                notify_slot_available,
            } => match item {
                Ok(bytes) => {
                    let released = bytes.len();
                    self.release_recv_bytes(released, notify_slot_available);
                    self.reset_read_idle();
                    if bytes.is_empty() {
                        return self.poll_frame(cx);
                    }
                    return Poll::Ready(Some(Ok(Frame::data(bytes))));
                }
                Err(error) => {
                    self.terminal = true;
                    self.shared.close();
                    return Poll::Ready(Some(Err(error)));
                }
            },
        }

        if self.timeouts_enabled() {
            if let Some(total_sleep) = self.total_sleep.as_mut() {
                if total_sleep.as_mut().poll(cx).is_ready() {
                    let duration = self.total_timeout.expect("total sleep without duration");
                    return self.close_with_error(Error::TotalTimeout(duration));
                }
            }

            if let Some(read_idle_sleep) = self.read_idle_sleep.as_mut() {
                if read_idle_sleep.as_mut().poll(cx).is_ready() {
                    let duration = self
                        .read_idle_timeout
                        .expect("read-idle sleep without duration");
                    return self.close_with_error(Error::ReadIdleTimeout(duration));
                }
            }
        }

        Poll::Pending
    }

    fn is_end_stream(&self) -> bool {
        self.terminal
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}
