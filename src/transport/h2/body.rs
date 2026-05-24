//! Poll-based HTTP/2 response body delivery.

use bytes::Bytes;
use http_body::{Body as HttpBody, Frame, SizeHint};
use std::collections::VecDeque;
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
pub struct H2BodyTimeouts {
    pub(crate) read_idle: Option<Duration>,
    pub(crate) total: Option<Duration>,
}

pub(crate) enum H2BodyPush {
    Accepted,
    Full(std::result::Result<Bytes, Error>),
    Closed,
}

#[derive(Default)]
struct H2BodyState {
    slot: Option<std::result::Result<Bytes, Error>>,
    terminal_error: Option<Error>,
    ended: bool,
    closed: bool,
    consumer_waker: Option<Waker>,
    transitions: VecDeque<&'static str>,
}

/// Shared DATA slot between the H2 driver and the public `Body` poller.
pub struct H2BodyShared {
    state: Mutex<H2BodyState>,
    released_recv_bytes: AtomicUsize,
    driver_notify: Arc<Notify>,
}

impl H2BodyShared {
    pub(crate) fn new(driver_notify: Arc<Notify>) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(H2BodyState::default()),
            released_recv_bytes: AtomicUsize::new(0),
            driver_notify,
        })
    }

    pub(crate) fn push(&self, item: std::result::Result<Bytes, Error>) -> H2BodyPush {
        let mut state = self.state.lock().expect("h2 body state poisoned");
        if state.closed {
            return H2BodyPush::Closed;
        }
        if state.slot.is_some() {
            return H2BodyPush::Full(item);
        }
        state.transitions.push_back("driver_slot_fill");
        state.slot = Some(item);
        if let Some(waker) = state.consumer_waker.take() {
            waker.wake();
        }
        H2BodyPush::Accepted
    }

    pub(crate) fn finish(&self) {
        let mut state = self.state.lock().expect("h2 body state poisoned");
        state.ended = true;
        state.transitions.push_back("driver_finish");
        if let Some(waker) = state.consumer_waker.take() {
            waker.wake();
        }
    }

    pub(crate) fn fail(&self, error: Error) -> H2BodyPush {
        let mut state = self.state.lock().expect("h2 body state poisoned");
        if state.closed {
            return H2BodyPush::Closed;
        }
        if state.slot.is_some() {
            return H2BodyPush::Full(Err(error));
        }
        state.slot = Some(Err(error));
        state.transitions.push_back("driver_error");
        if let Some(waker) = state.consumer_waker.take() {
            waker.wake();
        }
        H2BodyPush::Accepted
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.state.lock().expect("h2 body state poisoned").closed
    }

    pub(crate) fn is_slot_available(&self) -> bool {
        let state = self.state.lock().expect("h2 body state poisoned");
        !state.closed && state.slot.is_none()
    }

    pub(crate) fn take_released_recv_bytes(&self) -> usize {
        self.released_recv_bytes.swap(0, Ordering::AcqRel)
    }

    pub(crate) fn has_released_recv_bytes(&self) -> bool {
        self.released_recv_bytes.load(Ordering::Acquire) > 0
    }

    fn close(&self) {
        let mut state = self.state.lock().expect("h2 body state poisoned");
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

/// HTTP/2 response body backed by driver-owned wakeable state.
pub(crate) struct H2Body {
    shared: Arc<H2BodyShared>,
    read_idle_timeout: Option<Duration>,
    read_idle_sleep: Option<Pin<Box<Sleep>>>,
    total_timeout: Option<Duration>,
    total_sleep: Option<Pin<Box<Sleep>>>,
    terminal: bool,
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
            Item(std::result::Result<Bytes, Error>),
            Error(Error),
            End,
            Pending,
        }

        let state_poll = {
            let mut state = self.shared.state.lock().expect("h2 body state poisoned");
            if let Some(item) = state.slot.take() {
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
                        .fetch_add(bytes.len(), Ordering::AcqRel);
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
