use bytes::Bytes;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::Notify;

use crate::error::{Error, Result};

/// Outbound bytes queued by an RFC 8441 tunnel handle for the H2 driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H2TunnelOutbound {
    pub bytes: Bytes,
    pub end_stream: bool,
}

/// Inbound tunnel event delivered by the H2 driver to the tunnel handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum H2TunnelEvent {
    Data(Bytes),
    EndStream,
    Reset(String),
    GoAway { last_stream_id: u32 },
}

const MAX_RELEASE_NOTIFY_BYTES: usize = 512 * 1024;

#[derive(Debug)]
pub(crate) struct H2TunnelCredit {
    released_recv_bytes: AtomicUsize,
    release_notify_bytes: usize,
    driver_notify: Arc<Notify>,
}

impl H2TunnelCredit {
    pub(crate) fn new(driver_notify: Arc<Notify>, initial_window_size: u32) -> Arc<Self> {
        let release_notify_bytes =
            ((initial_window_size as usize) / 4).clamp(1, MAX_RELEASE_NOTIFY_BYTES);
        Arc::new(Self {
            released_recv_bytes: AtomicUsize::new(0),
            release_notify_bytes,
            driver_notify,
        })
    }

    pub(crate) fn take_released_recv_bytes(&self) -> usize {
        self.released_recv_bytes.swap(0, Ordering::Relaxed)
    }
}

/// Byte transport for an RFC 8441 tunnel stream.
#[derive(Debug)]
pub struct H2Tunnel {
    outbound_tx: mpsc::Sender<H2TunnelOutbound>,
    inbound_rx: mpsc::Receiver<Result<H2TunnelEvent>>,
    credit: Option<Arc<H2TunnelCredit>>,
    pending_release_bytes: usize,
}

impl H2Tunnel {
    pub fn new(
        outbound_tx: mpsc::Sender<H2TunnelOutbound>,
        inbound_rx: mpsc::Receiver<Result<H2TunnelEvent>>,
    ) -> Self {
        Self {
            outbound_tx,
            inbound_rx,
            credit: None,
            pending_release_bytes: 0,
        }
    }

    pub(crate) fn new_with_credit(
        outbound_tx: mpsc::Sender<H2TunnelOutbound>,
        inbound_rx: mpsc::Receiver<Result<H2TunnelEvent>>,
        credit: Arc<H2TunnelCredit>,
    ) -> Self {
        Self {
            outbound_tx,
            inbound_rx,
            credit: Some(credit),
            pending_release_bytes: 0,
        }
    }

    pub async fn send_bytes(&self, bytes: Bytes, end_stream: bool) -> Result<()> {
        self.outbound_tx
            .send(H2TunnelOutbound { bytes, end_stream })
            .await
            .map_err(|_| Error::HttpProtocol("H2 tunnel outbound channel closed".into()))
    }

    pub async fn close_send(&self) -> Result<()> {
        self.send_bytes(Bytes::new(), true).await
    }

    pub async fn recv_event(&mut self) -> Option<Result<H2TunnelEvent>> {
        let event = self.inbound_rx.recv().await?;
        if let Ok(H2TunnelEvent::Data(bytes)) = &event {
            self.release_recv_bytes(bytes.len());
        }
        Some(event)
    }

    pub async fn recv_bytes(&mut self) -> Option<Result<Bytes>> {
        match self.recv_event().await? {
            Ok(H2TunnelEvent::Data(bytes)) => Some(Ok(bytes)),
            Ok(H2TunnelEvent::EndStream) => None,
            Ok(H2TunnelEvent::Reset(reason)) => Some(Err(Error::HttpProtocol(format!(
                "H2 tunnel reset: {reason}"
            )))),
            Ok(H2TunnelEvent::GoAway { last_stream_id }) => Some(Err(Error::HttpProtocol(
                format!("H2 tunnel closed by GOAWAY last_stream_id={last_stream_id}"),
            ))),
            Err(err) => Some(Err(err)),
        }
    }

    fn release_recv_bytes(&mut self, released: usize) {
        let Some(credit) = self.credit.as_ref() else {
            return;
        };
        self.pending_release_bytes = self.pending_release_bytes.saturating_add(released);
        if self.pending_release_bytes >= credit.release_notify_bytes {
            let released = std::mem::take(&mut self.pending_release_bytes);
            credit
                .released_recv_bytes
                .fetch_add(released, Ordering::Relaxed);
            credit.driver_notify.notify_one();
        }
    }
}

impl Drop for H2Tunnel {
    fn drop(&mut self) {
        let Some(credit) = self.credit.as_ref() else {
            return;
        };
        if self.pending_release_bytes > 0 {
            let released = std::mem::take(&mut self.pending_release_bytes);
            credit
                .released_recv_bytes
                .fetch_add(released, Ordering::Relaxed);
        }
        credit.driver_notify.notify_one();
    }
}
