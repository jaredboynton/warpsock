use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

pub async fn wait_until(mut cond: impl FnMut() -> bool, timeout: Duration) -> bool {
    tokio::time::timeout(timeout, async move {
        loop {
            if cond() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap_or(false)
}

pub async fn wait_for_count(count: &AtomicUsize, expected: usize, timeout: Duration) -> bool {
    wait_until(|| count.load(Ordering::SeqCst) >= expected, timeout).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn wait_until_observes_condition_change() {
        let ready = Arc::new(AtomicUsize::new(0));
        let ready_for_task = Arc::clone(&ready);

        tokio::spawn(async move {
            tokio::task::yield_now().await;
            ready_for_task.store(1, Ordering::SeqCst);
        });

        assert!(wait_until(|| ready.load(Ordering::SeqCst) == 1, Duration::from_secs(1),).await);
    }

    #[tokio::test]
    async fn wait_for_count_times_out_without_expected_count() {
        let count = AtomicUsize::new(1);

        let started = Instant::now();
        assert!(!wait_for_count(&count, 2, Duration::from_millis(5)).await);
        assert!(started.elapsed() >= Duration::from_millis(5));
    }
}
