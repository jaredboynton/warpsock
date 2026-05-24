use bytes::Bytes;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::Notify;
use tokio::sync::Semaphore;

use crate::error::{Error, Result};

/// Outbound bytes queued by an RFC 9220 tunnel handle for the H3 driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H3TunnelOutbound {
    pub bytes: Bytes,
    pub fin: bool,
}

/// Inbound tunnel event delivered by the H3 driver to the tunnel handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum H3TunnelEvent {
    Data(Bytes),
    EndStream,
    Reset(String),
    GoAway { id: u64 },
}

/// Cap on the outbound byte budget. Tokio's `Semaphore` permits are `usize`,
/// but acquisitions are `u32`-bounded internally; pinning the budget at
/// `u32::MAX as usize` keeps every cast lossless without putting an arbitrary
/// lower bound on the configured value.
pub(crate) const MAX_TUNNEL_OUTBOUND_BYTE_BUDGET: usize = u32::MAX as usize;

#[derive(Debug)]
pub(crate) struct H3TunnelCredit {
    released_recv_bytes: AtomicUsize,
    driver_notify: Arc<Notify>,
    /// Permits represent bytes still available to push into the outbound
    /// pipeline (`H3Tunnel` channel + driver `pending_outbound` queue +
    /// in-flight wire bytes). `send_bytes` acquires `min(bytes.len(), budget)`
    /// permits and `forget`s them; the driver `add_permits` them back as it
    /// transmits each chunk on the wire.
    send_semaphore: Arc<Semaphore>,
    /// Permits initially available. Acquired permits per send are capped at
    /// this value so a single oversized send waits for the queue to fully
    /// drain rather than being split, and the same value bounds the
    /// per-outbound credit accounting on the driver side.
    send_budget: usize,
}

impl H3TunnelCredit {
    pub(crate) fn new(driver_notify: Arc<Notify>, send_budget: usize) -> Arc<Self> {
        let send_budget = send_budget.min(MAX_TUNNEL_OUTBOUND_BYTE_BUDGET);
        Arc::new(Self {
            released_recv_bytes: AtomicUsize::new(0),
            driver_notify,
            send_semaphore: Arc::new(Semaphore::new(send_budget)),
            send_budget,
        })
    }

    pub(crate) fn take_released_recv_bytes(&self) -> usize {
        self.released_recv_bytes.swap(0, Ordering::Relaxed)
    }

    pub(crate) fn release_send_bytes(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        let capped = bytes.min(self.send_budget);
        self.send_semaphore.add_permits(capped);
    }

    #[cfg(test)]
    pub(crate) fn available_send_permits(&self) -> usize {
        self.send_semaphore.available_permits()
    }
}

/// Byte transport for an RFC 9220 WebSocket-over-HTTP/3 tunnel stream.
#[derive(Debug)]
pub struct H3Tunnel {
    outbound_tx: mpsc::UnboundedSender<H3TunnelOutbound>,
    inbound_rx: mpsc::Receiver<Result<H3TunnelEvent>>,
    credit: Option<Arc<H3TunnelCredit>>,
}

impl H3Tunnel {
    pub fn new(
        outbound_tx: mpsc::UnboundedSender<H3TunnelOutbound>,
        inbound_rx: mpsc::Receiver<Result<H3TunnelEvent>>,
    ) -> Self {
        Self {
            outbound_tx,
            inbound_rx,
            credit: None,
        }
    }

    pub(crate) fn new_with_credit(
        outbound_tx: mpsc::UnboundedSender<H3TunnelOutbound>,
        inbound_rx: mpsc::Receiver<Result<H3TunnelEvent>>,
        credit: Arc<H3TunnelCredit>,
    ) -> Self {
        Self {
            outbound_tx,
            inbound_rx,
            credit: Some(credit),
        }
    }

    pub async fn send_bytes(&self, bytes: Bytes, fin: bool) -> Result<()> {
        // close_send (and any zero-byte send) skips the byte-credit semaphore so
        // a fin can always be queued even when the budget is exhausted.
        if !bytes.is_empty() {
            if let Some(credit) = self.credit.as_ref() {
                let to_acquire = bytes.len().min(credit.send_budget);
                let permit = credit
                    .send_semaphore
                    .acquire_many(to_acquire as u32)
                    .await
                    .map_err(|_| Error::HttpProtocol("H3 tunnel outbound credit closed".into()))?;
                permit.forget();
            }
        }
        self.outbound_tx
            .send(H3TunnelOutbound { bytes, fin })
            .map_err(|_| Error::HttpProtocol("H3 tunnel outbound channel closed".into()))
    }

    pub async fn close_send(&self) -> Result<()> {
        self.send_bytes(Bytes::new(), true).await
    }

    pub async fn recv_event(&mut self) -> Option<Result<H3TunnelEvent>> {
        let event = self.inbound_rx.recv().await?;
        if let Ok(H3TunnelEvent::Data(bytes)) = &event {
            self.release_recv_bytes(bytes.len());
        } else if let Some(credit) = self.credit.as_ref() {
            credit.driver_notify.notify_one();
        }
        Some(event)
    }

    pub async fn recv_bytes(&mut self) -> Option<Result<Bytes>> {
        match self.recv_event().await? {
            Ok(H3TunnelEvent::Data(bytes)) => Some(Ok(bytes)),
            Ok(H3TunnelEvent::EndStream) => None,
            Ok(H3TunnelEvent::Reset(reason)) => Some(Err(Error::HttpProtocol(format!(
                "H3 tunnel reset: {reason}"
            )))),
            Ok(H3TunnelEvent::GoAway { id }) => Some(Err(Error::HttpProtocol(format!(
                "H3 tunnel closed by GOAWAY id={id}"
            )))),
            Err(err) => Some(Err(err)),
        }
    }

    fn release_recv_bytes(&self, released: usize) {
        let Some(credit) = self.credit.as_ref() else {
            return;
        };
        if released > 0 {
            credit
                .released_recv_bytes
                .fetch_add(released, Ordering::Relaxed);
        }
        credit.driver_notify.notify_one();
    }
}
