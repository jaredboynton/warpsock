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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Mutex as TokioMutex;
    use tokio::time::{sleep, timeout};

    /// Drives the outbound side of a tunnel: drain the unbounded channel and
    /// hand each chunk to the driver-side credit-release callback under a
    /// configurable per-chunk delay. The release path mirrors what
    /// `flush_tunnel_data_once` does on the wire send path - it never returns
    /// more than `acquired_credit` worth of permits per outbound, so this is a
    /// faithful stand-in for the byte-bounded backpressure contract.
    struct OutboundDrainer {
        outbound_rx: TokioMutex<mpsc::UnboundedReceiver<H3TunnelOutbound>>,
        credit: Arc<H3TunnelCredit>,
        chunk_size: usize,
        per_chunk_delay: Duration,
        peak_in_flight: Arc<AtomicUsize>,
    }

    impl OutboundDrainer {
        fn new(
            outbound_rx: mpsc::UnboundedReceiver<H3TunnelOutbound>,
            credit: Arc<H3TunnelCredit>,
            chunk_size: usize,
            per_chunk_delay: Duration,
        ) -> Arc<Self> {
            Arc::new(Self {
                outbound_rx: TokioMutex::new(outbound_rx),
                credit,
                chunk_size,
                per_chunk_delay,
                peak_in_flight: Arc::new(AtomicUsize::new(0)),
            })
        }

        async fn run(self: Arc<Self>) -> Vec<H3TunnelOutbound> {
            let mut collected = Vec::new();
            let mut rx = self.outbound_rx.lock().await;
            while let Some(outbound) = rx.recv().await {
                let budget = self.credit.send_budget;
                let acquired = outbound.bytes.len().min(budget);

                // Observe peak in-flight as bytes that have been admitted past the
                // semaphore but not yet released back to it.
                let in_flight = budget - self.credit.available_send_permits();
                self.peak_in_flight
                    .fetch_max(in_flight, AtomicOrdering::SeqCst);

                let mut released = 0usize;
                let total = outbound.bytes.len();
                if total == 0 {
                    // close_send: no credit was acquired, nothing to release.
                    collected.push(outbound.clone());
                    if outbound.fin {
                        // signal the test that the producer is done
                        return collected;
                    }
                    continue;
                }
                let mut offset = 0usize;
                while offset < total {
                    let chunk = self.chunk_size.min(total - offset);
                    if !self.per_chunk_delay.is_zero() {
                        sleep(self.per_chunk_delay).await;
                    }
                    let release_now = chunk.min(acquired.saturating_sub(released));
                    if release_now > 0 {
                        self.credit.release_send_bytes(release_now);
                        released = released.saturating_add(release_now);
                    }
                    offset += chunk;
                }
                if released < acquired {
                    self.credit.release_send_bytes(acquired - released);
                }
                collected.push(outbound);
            }
            collected
        }
    }

    fn make_tunnel(
        budget: usize,
    ) -> (
        H3Tunnel,
        mpsc::UnboundedReceiver<H3TunnelOutbound>,
        Arc<H3TunnelCredit>,
    ) {
        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel::<H3TunnelOutbound>();
        let (_inbound_tx, inbound_rx) = mpsc::channel::<Result<H3TunnelEvent>>(1);
        let credit = H3TunnelCredit::new(Arc::new(Notify::new()), budget);
        let tunnel = H3Tunnel::new_with_credit(outbound_tx, inbound_rx, credit.clone());
        (tunnel, outbound_rx, credit)
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn send_larger_than_budget_blocks_until_consumer_drains() {
        let budget = 64 * 1024;
        let (tunnel, outbound_rx, credit) = make_tunnel(budget);

        // Prefill: drain every credit permit before the producer starts. This
        // guarantees the producer's first `send_bytes` must observe the
        // drainer releasing permits in order to proceed; otherwise the test
        // could not distinguish byte-bounded backpressure from a no-op
        // semaphore.
        let prefill = credit
            .send_semaphore
            .clone()
            .try_acquire_many_owned(budget as u32)
            .expect("must reserve every permit before the producer starts");
        std::mem::forget(prefill);
        assert_eq!(credit.available_send_permits(), 0);

        // 4x budget single producer payload + a small follow-up so the test
        // also exercises the "oversized chunk waits, then a normal-sized chunk
        // succeeds once enough credit is back" path. The drainer releases
        // permits in small slices so producers genuinely contend for budget.
        let payload_size = 4 * budget;
        let payload = Bytes::from(vec![0x42u8; payload_size]);
        let follow_up = Bytes::from(vec![0x21u8; budget / 2]);

        let drainer = OutboundDrainer::new(
            outbound_rx,
            credit.clone(),
            budget / 8,
            Duration::from_millis(1),
        );
        let drainer_handle = {
            let drainer = drainer.clone();
            tokio::spawn(async move { drainer.run().await })
        };

        let tunnel = Arc::new(tunnel);
        let producer = {
            let tunnel = tunnel.clone();
            let payload = payload.clone();
            let follow_up = follow_up.clone();
            tokio::spawn(async move {
                tunnel
                    .send_bytes(payload, false)
                    .await
                    .expect("oversized send_bytes must complete once credit is released");
                tunnel
                    .send_bytes(follow_up, false)
                    .await
                    .expect("follow-up send_bytes must complete");
                tunnel
                    .send_bytes(Bytes::new(), true)
                    .await
                    .expect("close_send must complete even after credit is drained");
            })
        };

        // Release the prefilled credit so the producer can make initial
        // progress; from there the drainer keeps refunding credit as it
        // observes the producer's chunks.
        credit.release_send_bytes(budget);

        timeout(Duration::from_secs(5), producer)
            .await
            .expect("producer must not deadlock when sending more than budget")
            .expect("producer task panicked");

        let collected = drainer_handle.await.expect("drainer task did not panic");
        let total_collected: usize = collected.iter().map(|o| o.bytes.len()).sum();
        assert_eq!(
            total_collected,
            payload_size + follow_up.len(),
            "drainer must have observed every byte the producer queued"
        );
        assert!(
            collected.last().expect("at least one outbound").fin,
            "last drained outbound must carry the producer's close_send fin"
        );
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn two_producers_respect_total_byte_budget() {
        let budget = 8 * 1024;
        let (tunnel, outbound_rx, credit) = make_tunnel(budget);

        let drainer =
            OutboundDrainer::new(outbound_rx, credit.clone(), 512, Duration::from_millis(2));
        let peak_in_flight = drainer.peak_in_flight.clone();
        let drainer_handle = {
            let drainer = drainer.clone();
            tokio::spawn(async move { drainer.run().await })
        };

        // Two concurrent producers race for the same credit semaphore via
        // `tokio::join!`. Sharing `&tunnel` across two futures on the same
        // task is enough to exercise interleaving without requiring
        // `H3Tunnel: Sync` (mpsc::Receiver is `!Sync`).
        let tunnel_ref = &tunnel;
        let producer_a = async move {
            for _ in 0..6 {
                tunnel_ref
                    .send_bytes(Bytes::from(vec![1u8; 2 * 1024]), false)
                    .await
                    .expect("producer A send_bytes");
            }
        };
        let producer_b = async move {
            for _ in 0..6 {
                tunnel_ref
                    .send_bytes(Bytes::from(vec![2u8; 2 * 1024]), false)
                    .await
                    .expect("producer B send_bytes");
            }
        };
        tokio::join!(producer_a, producer_b);

        // Final fin so the drainer exits.
        tunnel
            .send_bytes(Bytes::new(), true)
            .await
            .expect("final fin send");
        drainer_handle.await.expect("drainer did not panic");

        let observed_peak = peak_in_flight.load(AtomicOrdering::SeqCst);
        assert!(
            observed_peak <= budget,
            "peak in-flight bytes {observed_peak} must not exceed the configured budget {budget}",
        );
        // Sanity check that the producers actually shared the pipe (otherwise
        // the bound above is uninteresting).
        assert!(
            observed_peak >= 2 * 1024,
            "peak in-flight should be at least one full producer chunk (was {observed_peak})",
        );
    }

    #[tokio::test(start_paused = false)]
    async fn close_send_works_when_budget_is_exhausted() {
        let budget = 4 * 1024;
        let (tunnel, mut outbound_rx, credit) = make_tunnel(budget);

        // Drain all permits without ever returning them so the budget is exhausted.
        let drained = credit
            .send_semaphore
            .clone()
            .try_acquire_many_owned(budget as u32)
            .expect("must reserve every permit");
        std::mem::forget(drained);
        assert_eq!(credit.available_send_permits(), 0);

        // close_send is fin-only and must not block on the byte-credit semaphore.
        timeout(Duration::from_secs(2), tunnel.close_send())
            .await
            .expect("close_send must not block on the credit semaphore when budget is exhausted")
            .expect("close_send returned an error");

        let queued = outbound_rx
            .recv()
            .await
            .expect("close_send must enqueue an outbound with fin");
        assert!(queued.bytes.is_empty(), "close_send must send empty bytes");
        assert!(queued.fin, "close_send must mark the outbound as fin");
        // Nothing else should be in the queue.
        assert!(outbound_rx.try_recv().is_err());
    }

    #[test]
    fn release_send_bytes_is_capped_at_send_budget() {
        let budget = 16 * 1024;
        let credit = H3TunnelCredit::new(Arc::new(Notify::new()), budget);
        // Drain everything.
        let permit = credit
            .send_semaphore
            .clone()
            .try_acquire_many_owned(budget as u32)
            .expect("reserve every permit");
        std::mem::forget(permit);
        assert_eq!(credit.available_send_permits(), 0);

        // Releasing 4x the budget must not push the semaphore above its
        // configured ceiling; otherwise the per-tunnel cap would lose meaning.
        credit.release_send_bytes(4 * budget);
        assert_eq!(credit.available_send_permits(), budget);
    }
}
