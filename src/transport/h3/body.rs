//! Poll-based HTTP/3 response body delivery.

use bytes::Bytes;
use http_body::{Body as HttpBody, Frame, SizeHint};
use std::collections::VecDeque;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;
use tokio::sync::Notify;
use tokio::time::{sleep, Sleep};

use crate::error::Error;

#[derive(Clone, Copy, Debug, Default)]
pub struct H3BodyTimeouts {
    pub(crate) read_idle: Option<Duration>,
    pub(crate) total: Option<Duration>,
}

#[derive(Debug)]
pub(crate) enum H3BodyPush {
    Accepted,
    Full,
    Closed,
}

/// Default bounded in-flight DATA item capacity per H3 stream body.
pub(crate) const DEFAULT_H3_BODY_SLOT_CAPACITY: usize = 64;

struct H3BodyState {
    slots: VecDeque<std::result::Result<Bytes, Error>>,
    cap: usize,
    terminal_error: Option<Error>,
    ended: bool,
    closed: bool,
    consumer_waker: Option<Waker>,
    transitions: VecDeque<&'static str>,
}

impl Default for H3BodyState {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_H3_BODY_SLOT_CAPACITY)
    }
}

impl H3BodyState {
    fn with_capacity(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            slots: VecDeque::with_capacity(capacity),
            cap: capacity,
            terminal_error: None,
            ended: false,
            closed: false,
            consumer_waker: None,
            transitions: VecDeque::new(),
        }
    }
}

/// Shared DATA slots between the H3 driver and the public `Body` poller.
///
/// Bounded `VecDeque` plus consumer `Waker` and driver `Notify`. The cap is a
/// safety bound on in-flight chunks; QUIC stream-level flow control still
/// bounds total in-flight bytes.
pub struct H3BodyShared {
    state: Mutex<H3BodyState>,
    released_recv_bytes: AtomicUsize,
    driver_notify: Arc<Notify>,
}

impl fmt::Debug for H3BodyShared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state.lock().expect("h3 body state poisoned");
        f.debug_struct("H3BodyShared")
            .field("slot_count", &state.slots.len())
            .field("cap", &state.cap)
            .field("ended", &state.ended)
            .field("closed", &state.closed)
            .finish()
    }
}

impl H3BodyShared {
    pub(crate) fn new_with_capacity(driver_notify: Arc<Notify>, capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(H3BodyState::with_capacity(capacity)),
            released_recv_bytes: AtomicUsize::new(0),
            driver_notify,
        })
    }

    pub(crate) fn push(&self, item: std::result::Result<Bytes, Error>) -> H3BodyPush {
        let mut state = self.state.lock().expect("h3 body state poisoned");
        if state.closed {
            return H3BodyPush::Closed;
        }
        if state.slots.len() >= state.cap {
            return H3BodyPush::Full;
        }
        state.transitions.push_back("driver_slot_fill");
        state.slots.push_back(item);
        if let Some(waker) = state.consumer_waker.take() {
            waker.wake();
        }
        H3BodyPush::Accepted
    }

    pub(crate) fn finish(&self) {
        let mut state = self.state.lock().expect("h3 body state poisoned");
        state.ended = true;
        state.transitions.push_back("driver_finish");
        if let Some(waker) = state.consumer_waker.take() {
            waker.wake();
        }
    }

    pub(crate) fn fail(&self, error: Error) -> H3BodyPush {
        let mut state = self.state.lock().expect("h3 body state poisoned");
        if state.closed {
            return H3BodyPush::Closed;
        }
        if state.slots.len() >= state.cap {
            if state.terminal_error.is_none() {
                state.terminal_error = Some(error);
                state.transitions.push_back("driver_terminal_error");
                if let Some(waker) = state.consumer_waker.take() {
                    waker.wake();
                }
            }
            return H3BodyPush::Accepted;
        }
        state.slots.push_back(Err(error));
        state.transitions.push_back("driver_error");
        if let Some(waker) = state.consumer_waker.take() {
            waker.wake();
        }
        H3BodyPush::Accepted
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.state.lock().expect("h3 body state poisoned").closed
    }

    pub(crate) fn is_slot_available(&self) -> bool {
        let state = self.state.lock().expect("h3 body state poisoned");
        !state.closed && state.slots.len() < state.cap
    }

    pub(crate) fn take_released_recv_bytes(&self) -> usize {
        self.released_recv_bytes.swap(0, Ordering::Relaxed)
    }

    fn close(&self) {
        let mut state = self.state.lock().expect("h3 body state poisoned");
        if !state.closed {
            state.closed = true;
            state.transitions.push_back("consumer_closed");
            if let Some(waker) = state.consumer_waker.take() {
                waker.wake();
            }
            self.driver_notify.notify_one();
        }
    }
}

/// HTTP/3 response body backed by driver-owned wakeable state.
pub(crate) struct H3Body {
    shared: Arc<H3BodyShared>,
    read_idle_timeout: Option<Duration>,
    read_idle_sleep: Option<Pin<Box<Sleep>>>,
    total_timeout: Option<Duration>,
    total_sleep: Option<Pin<Box<Sleep>>>,
    terminal: bool,
}

impl H3Body {
    pub(crate) fn new(shared: Arc<H3BodyShared>, timeouts: H3BodyTimeouts) -> Self {
        Self {
            shared,
            read_idle_timeout: timeouts.read_idle,
            read_idle_sleep: timeouts.read_idle.map(|duration| Box::pin(sleep(duration))),
            total_timeout: timeouts.total,
            total_sleep: timeouts.total.map(|duration| Box::pin(sleep(duration))),
            terminal: false,
        }
    }

    pub(crate) fn is_terminal(&self) -> bool {
        self.terminal
    }

    fn reset_read_idle(&mut self) {
        if let Some(duration) = self.read_idle_timeout {
            self.read_idle_sleep = Some(Box::pin(sleep(duration)));
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

impl Drop for H3Body {
    fn drop(&mut self) {
        if !self.terminal {
            self.shared.close();
        }
    }
}

impl HttpBody for H3Body {
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
            Item(std::result::Result<Bytes, Error>),
            Error(Error),
            End,
            Pending,
        }

        let state_poll = {
            let mut state = self.shared.state.lock().expect("h3 body state poisoned");
            if let Some(item) = state.slots.pop_front() {
                state.transitions.push_back("consumer_slot_take");
                StatePoll::Item(item)
            } else if let Some(error) = state.terminal_error.take() {
                state.closed = true;
                StatePoll::Error(error)
            } else if state.ended {
                state.closed = true;
                StatePoll::End
            } else {
                state.consumer_waker = Some(cx.waker().clone());
                self.shared.driver_notify.notify_one();
                StatePoll::Pending
            }
        };

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
            StatePoll::Item(item) => match item {
                Ok(bytes) => {
                    self.shared
                        .released_recv_bytes
                        .fetch_add(bytes.len(), Ordering::Relaxed);
                    self.shared.driver_notify.notify_one();
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

        Poll::Pending
    }

    fn is_end_stream(&self) -> bool {
        self.terminal
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h3_body_shared_uses_configured_slot_capacity() {
        let shared = H3BodyShared::new_with_capacity(Arc::new(Notify::new()), 2);

        assert!(matches!(
            shared.push(Ok(Bytes::from_static(b"one"))),
            H3BodyPush::Accepted
        ));
        assert!(matches!(
            shared.push(Ok(Bytes::from_static(b"two"))),
            H3BodyPush::Accepted
        ));
        assert!(matches!(
            shared.push(Ok(Bytes::from_static(b"three"))),
            H3BodyPush::Full
        ));
    }

    #[test]
    fn h3_body_reports_released_recv_bytes_when_consumer_takes_data() {
        struct NoopWake;

        impl std::task::Wake for NoopWake {
            fn wake(self: Arc<Self>) {}
        }

        let shared = H3BodyShared::new_with_capacity(Arc::new(Notify::new()), 2);
        assert!(matches!(
            shared.push(Ok(Bytes::from_static(b"hello"))),
            H3BodyPush::Accepted
        ));

        let mut body = H3Body::new(shared.clone(), H3BodyTimeouts::default());
        let waker = std::task::Waker::from(Arc::new(NoopWake));
        let mut context = Context::from_waker(&waker);

        assert_eq!(shared.take_released_recv_bytes(), 0);
        let frame = Pin::new(&mut body).poll_frame(&mut context);
        assert!(matches!(frame, Poll::Ready(Some(Ok(_)))));
        assert_eq!(shared.take_released_recv_bytes(), 5);
        assert_eq!(shared.take_released_recv_bytes(), 0);
    }
}
