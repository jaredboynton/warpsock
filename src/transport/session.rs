//! TLS session resumption and caching for TCP-TLS connections.
//!
//! BoringSSL does not retain client sessions in its internal cache. Callers must
//! install `SSL_CTX_sess_set_new_cb`, store tickets externally, and replay them
//! with `SSL_set_session` on subsequent dials.

use boring::ssl::SslSession;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Notify;

/// Cache key for a TLS session ticket.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct SessionCacheKey {
    pub host: String,
    pub port: u16,
}

impl SessionCacheKey {
    pub fn new(host: &str, port: u16) -> Self {
        Self {
            host: host.trim_end_matches('.').to_ascii_lowercase(),
            port,
        }
    }
}

#[derive(Debug, Clone)]
struct CachedSession {
    der: Vec<u8>,
    early_data_capable: bool,
    max_age: Duration,
    received_at: Instant,
}

/// Host-keyed TLS session ticket cache shared across connector clones.
#[derive(Debug, Clone)]
pub struct SessionCache {
    inner: Arc<Mutex<SessionCacheInner>>,
    session_stored: Arc<Notify>,
}

#[derive(Debug)]
struct SessionCacheInner {
    sessions: HashMap<SessionCacheKey, CachedSession>,
    default_max_age: Duration,
}

impl SessionCache {
    /// Create a new session cache with default max age (24 hours).
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(SessionCacheInner {
                sessions: HashMap::new(),
                default_max_age: Duration::from_secs(86400),
            })),
            session_stored: Arc::new(Notify::new()),
        }
    }

    /// Create a session cache with custom default max age.
    pub fn with_max_age(max_age: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(SessionCacheInner {
                sessions: HashMap::new(),
                default_max_age: max_age,
            })),
            session_stored: Arc::new(Notify::new()),
        }
    }

    /// Store a serialized TLS session for later resumption.
    pub fn store_session(
        &self,
        key: SessionCacheKey,
        der: Vec<u8>,
        early_data_capable: bool,
        max_age: Option<Duration>,
    ) {
        {
            let mut inner = self.inner.lock().expect("Session cache mutex poisoned");
            let max_age = max_age.unwrap_or(inner.default_max_age);
            inner.sessions.insert(
                key,
                CachedSession {
                    der,
                    early_data_capable,
                    max_age,
                    received_at: Instant::now(),
                },
            );
        }
        self.session_stored.notify_waiters();
    }

    /// Legacy host-only store API retained for compatibility.
    pub fn store_ticket(&self, host: &str, ticket_data: Vec<u8>, max_age: Option<Duration>) {
        self.store_session(
            SessionCacheKey::new(host, 443),
            ticket_data,
            false,
            max_age,
        );
    }

    /// Load a cached session if still valid.
    pub fn get_session(&self, key: &SessionCacheKey) -> Option<SslSession> {
        let mut inner = self.inner.lock().expect("Session cache mutex poisoned");
        let entry = inner.sessions.get(key)?.clone();
        if entry.received_at.elapsed() >= entry.max_age {
            inner.sessions.remove(key);
            return None;
        }
        SslSession::from_der(&entry.der).ok()
    }

    /// Wait until a session for `key` is stored or `timeout` elapses.
    pub async fn wait_for_session(&self, key: &SessionCacheKey, timeout: Duration) -> bool {
        tokio::time::timeout(timeout, async {
            loop {
                if self.has_session(key) {
                    return;
                }
                let notified = self.session_stored.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if self.has_session(key) {
                    return;
                }
                notified.await;
            }
        })
        .await
        .is_ok()
    }

    fn has_session(&self, key: &SessionCacheKey) -> bool {
        let mut inner = self.inner.lock().expect("Session cache mutex poisoned");
        let Some(entry) = inner.sessions.get(key) else {
            return false;
        };
        if entry.received_at.elapsed() >= entry.max_age {
            inner.sessions.remove(key);
            return false;
        }
        true
    }

    /// Whether a cached session advertises TLS 1.3 early-data support.
    pub fn supports_zero_rtt(&self, key: &SessionCacheKey) -> bool {
        let mut inner = self.inner.lock().expect("Session cache mutex poisoned");
        let Some(entry) = inner.sessions.get(key) else {
            return false;
        };
        if entry.received_at.elapsed() >= entry.max_age {
            inner.sessions.remove(key);
            return false;
        }
        entry.early_data_capable
    }

    /// Legacy host-only lookup API retained for compatibility.
    pub fn get_ticket(&self, host: &str) -> Option<Vec<u8>> {
        let key = SessionCacheKey::new(host, 443);
        let mut inner = self.inner.lock().expect("Session cache mutex poisoned");
        let entry = inner.sessions.get(&key)?.clone();
        if entry.received_at.elapsed() >= entry.max_age {
            inner.sessions.remove(&key);
            return None;
        }
        Some(entry.der.clone())
    }

    /// Clear all cached sessions.
    pub fn clear(&self) {
        let mut inner = self.inner.lock().expect("Session cache mutex poisoned");
        inner.sessions.clear();
    }

    /// Remove expired sessions.
    pub fn cleanup_expired(&self) {
        let mut inner = self.inner.lock().expect("Session cache mutex poisoned");
        inner
            .sessions
            .retain(|_, entry| entry.received_at.elapsed() < entry.max_age);
    }

    /// Number of cached sessions.
    pub fn len(&self) -> usize {
        let inner = self.inner.lock().expect("Session cache mutex poisoned");
        inner.sessions.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for SessionCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_cache_store_and_retrieve() {
        let cache = SessionCache::new();
        cache.store_session(
            SessionCacheKey::new("example.com", 443),
            vec![1, 2, 3],
            false,
            None,
        );

        assert_eq!(
            cache
                .get_ticket("example.com")
                .expect("legacy lookup should work"),
            vec![1, 2, 3]
        );
        assert!(cache
            .get_session(&SessionCacheKey::new("other.com", 443))
            .is_none());
    }

    #[test]
    fn test_session_cache_clear() {
        let cache = SessionCache::new();
        cache.store_ticket("example.com", vec![1, 2, 3], None);
        cache.store_ticket("other.com", vec![4, 5, 6], None);

        assert_eq!(cache.len(), 2);
        cache.clear();
        assert_eq!(cache.len(), 0);
    }

    #[tokio::test]
    async fn wait_for_session_observes_preexisting_session() {
        let cache = SessionCache::new();
        let key = SessionCacheKey::new("example.com", 443);
        cache.store_session(key.clone(), vec![1, 2, 3], false, None);

        assert!(cache.wait_for_session(&key, Duration::from_millis(1)).await);
    }

    #[tokio::test]
    async fn store_session_notifies_after_releasing_cache_lock() {
        let cache = SessionCache::new();
        let key = SessionCacheKey::new("example.com", 443);
        let waiter = {
            let cache = cache.clone();
            let key = key.clone();
            tokio::spawn(async move {
                assert!(cache.wait_for_session(&key, Duration::from_secs(1)).await);
                let _guard = cache.inner.lock().expect("Session cache mutex poisoned");
            })
        };

        cache.store_session(key, vec![1, 2, 3], false, None);

        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("waiter must not block on a notification sent while the cache lock is held")
            .expect("waiter task must not panic");
    }
}
