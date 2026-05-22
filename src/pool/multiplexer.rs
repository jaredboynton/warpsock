//! Connection pool for HTTP/2 and HTTP/3 multiplexing
//!
//! This module provides connection pooling with support for:
//! - HTTP/1.1: One connection per request (no pooling)
//! - HTTP/2: Connection reuse with stream multiplexing
//! - HTTP/3: QUIC connection reuse with stream multiplexing

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing;

use crate::error::Result;
use crate::fingerprint::FingerprintProfile;
use crate::transport::connector::MaybeHttpsStream;
use crate::transport::h2::PseudoHeaderOrder;
use crate::version::HttpVersion;

/// Connection pool key identifying a unique host/port combination with fingerprint settings
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct PoolKey {
    pub host: String,
    pub port: u16,
    pub is_https: bool,
    pub fingerprint: FingerprintProfile,
    pub pseudo_order: PseudoHeaderOrder,
}

impl PoolKey {
    /// Create a new pool key
    pub fn new(
        host: String,
        port: u16,
        is_https: bool,
        fingerprint: FingerprintProfile,
        pseudo_order: PseudoHeaderOrder,
    ) -> Self {
        Self {
            host,
            port,
            is_https,
            fingerprint,
            pseudo_order,
        }
    }
}

/// Pool entry for HTTP/1.1 connections
#[derive(Debug)]
pub struct H1PoolEntry {
    pub stream: MaybeHttpsStream,
    pub last_used: Instant,
}

impl H1PoolEntry {
    pub fn new(stream: MaybeHttpsStream) -> Self {
        Self {
            stream,
            last_used: Instant::now(),
        }
    }

    pub fn is_expired(&self, max_idle: Duration) -> bool {
        self.last_used.elapsed() >= max_idle
    }
}

/// Pool entry tracking connection state and stream usage
#[derive(Debug, Clone)]
pub struct PoolEntry {
    pub version: HttpVersion,
    pub established_at: Instant,
    pub last_used: Instant,
    /// Number of active streams (for HTTP/2 and HTTP/3)
    pub active_streams: u32,
    /// Maximum concurrent streams (from SETTINGS for HTTP/2)
    pub max_streams: u32,
    /// Connection is still valid
    pub is_valid: bool,
}

impl PoolEntry {
    /// Create a new pool entry
    pub fn new(version: HttpVersion, max_streams: u32) -> Self {
        let now = Instant::now();
        Self {
            version,
            established_at: now,
            last_used: now,
            active_streams: 0,
            max_streams,
            is_valid: true,
        }
    }

    /// Check if this connection can handle another multiplexed stream
    pub fn can_multiplex(&self) -> bool {
        matches!(
            self.version,
            HttpVersion::Http2 | HttpVersion::Http3 | HttpVersion::Http3Only
        ) && self.active_streams < self.max_streams
            && self.is_valid
    }

    /// Attempt to acquire a stream slot
    pub fn acquire_stream(&mut self) -> bool {
        if self.can_multiplex() {
            self.active_streams += 1;
            self.last_used = Instant::now();
            true
        } else {
            false
        }
    }

    /// Release a stream slot
    pub fn release_stream(&mut self) {
        if self.active_streams > 0 {
            self.active_streams -= 1;
            self.last_used = Instant::now();
        }
    }

    /// Mark connection as invalid (connection error, GOAWAY frame, etc.)
    pub fn invalidate(&mut self) {
        self.is_valid = false;
    }

    /// Check if connection is expired based on idle time
    pub fn is_expired(&self, max_idle: Duration) -> bool {
        let age = Instant::now().duration_since(self.last_used);
        age >= max_idle
    }
}

/// Connection pool for reusing HTTP/1.1, HTTP/2, and HTTP/3 connections
pub struct ConnectionPool {
    entries: Arc<RwLock<HashMap<PoolKey, PoolEntry>>>,
    h1_idle: Arc<RwLock<HashMap<PoolKey, Vec<H1PoolEntry>>>>,
    max_idle_duration: Duration,
    #[allow(dead_code)] // Reserved for future connection limiting per host
    max_connections_per_host: usize,
    default_max_streams: u32,
}

impl ConnectionPool {
    /// Default maximum idle duration (30 seconds)
    const DEFAULT_MAX_IDLE: Duration = Duration::from_secs(30);

    /// Default maximum connections per host
    const DEFAULT_MAX_PER_HOST: usize = 6;

    /// Default maximum concurrent streams for HTTP/2 and HTTP/3
    const DEFAULT_MAX_STREAMS: u32 = 100;

    /// Create a new connection pool with default settings
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            h1_idle: Arc::new(RwLock::new(HashMap::new())),
            max_idle_duration: Self::DEFAULT_MAX_IDLE,
            max_connections_per_host: Self::DEFAULT_MAX_PER_HOST,
            default_max_streams: Self::DEFAULT_MAX_STREAMS,
        }
    }

    /// Create a connection pool with custom configuration
    pub fn with_config(max_idle: Duration, max_per_host: usize, max_streams: u32) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            h1_idle: Arc::new(RwLock::new(HashMap::new())),
            max_idle_duration: max_idle,
            max_connections_per_host: max_per_host,
            default_max_streams: max_streams,
        }
    }

    /// Get an idle HTTP/1.1 connection from the pool
    pub async fn get_h1(&self, key: &PoolKey) -> Option<MaybeHttpsStream> {
        let start = Instant::now();
        let mut pool = self.h1_idle.write().await;
        if let Some(entries) = pool.get_mut(key) {
            tracing::debug!("H1 Pool: {} entries for key {:?}", entries.len(), key);
            let initial_count = entries.len();
            while let Some(entry) = entries.pop() {
                if !entry.is_expired(self.max_idle_duration) {
                    tracing::debug!(
                        "H1 Pool: Reusing connection for {:?} (checked {} entries, took {:?})",
                        key,
                        initial_count - entries.len(),
                        start.elapsed()
                    );
                    return Some(entry.stream);
                }
                tracing::debug!(
                    "H1 Pool: Connection expired for {:?} (age: {:?})",
                    key,
                    entry.last_used.elapsed()
                );
            }
        } else {
            tracing::debug!("H1 Pool: No entries for key {:?}", key);
        }
        tracing::debug!(
            "H1 Pool: No reusable connection found for {:?} (took {:?})",
            key,
            start.elapsed()
        );
        None
    }

    /// Return an HTTP/1.1 connection to the pool
    pub async fn put_h1(&self, key: PoolKey, stream: MaybeHttpsStream) {
        if self.max_connections_per_host == 0 {
            return;
        }
        let start = Instant::now();
        tracing::debug!("H1 Pool: Returning connection for {:?}", key);
        let mut pool = self.h1_idle.write().await;
        let entries = pool.entry(key.clone()).or_default();
        let count_before = entries.len();
        while entries.len() >= self.max_connections_per_host {
            entries.remove(0);
        }
        entries.push(H1PoolEntry::new(stream));
        tracing::debug!(
            "H1 Pool: Returned connection for {:?} (pool size: {} -> {}, took {:?})",
            key,
            count_before,
            entries.len(),
            start.elapsed()
        );
    }

    /// Get an existing connection or signal that a new one should be created
    ///
    /// Returns:
    /// - `Ok(Some(entry))`: Reusable connection found (HTTP/2 or HTTP/3)
    /// - `Ok(None)`: No reusable connection, create new one
    pub async fn get_or_create(
        &self,
        key: &PoolKey,
        version: HttpVersion,
    ) -> Result<Option<PoolEntry>> {
        let start = Instant::now();
        let mut entries = self.entries.write().await;

        // HTTP/1.1 doesn't support multiplexing in this map - managed via get_h1/put_h1
        if version == HttpVersion::Http1_1 {
            return Ok(None);
        }

        // Check for existing valid connection with available stream slots
        if let Some(entry) = entries.get_mut(key) {
            let active_before = entry.active_streams;
            if entry.acquire_stream() {
                tracing::debug!(
                    "H2/H3 Pool: Reusing connection for {:?} (active streams: {} -> {}, took {:?})",
                    key,
                    active_before,
                    entry.active_streams,
                    start.elapsed()
                );
                return Ok(Some(entry.clone()));
            } else {
                tracing::debug!(
                    "H2/H3 Pool: Connection exists for {:?} but cannot multiplex (active: {}/{}, valid: {}, took {:?})",
                    key,
                    active_before,
                    entry.max_streams,
                    entry.is_valid,
                    start.elapsed()
                );
            }
        } else {
            tracing::debug!("H2/H3 Pool: No existing connection for {:?}", key);
        }

        // No reusable connection found - create new entry
        tracing::debug!(
            "H2/H3 Pool: Creating new connection entry for {:?} (took {:?})",
            key,
            start.elapsed()
        );
        let entry = PoolEntry::new(version, self.default_max_streams);
        entries.insert(key.clone(), entry.clone());

        Ok(Some(entry))
    }

    /// Release a stream slot back to the pool
    pub async fn release(&self, key: &PoolKey) {
        let mut entries = self.entries.write().await;
        if let Some(entry) = entries.get_mut(key) {
            let active_before = entry.active_streams;
            entry.release_stream();
            tracing::debug!(
                "H2/H3 Pool: Released stream for {:?} (active streams: {} -> {})",
                key,
                active_before,
                entry.active_streams
            );
        } else {
            tracing::warn!(
                "H2/H3 Pool: Attempted to release stream for non-existent connection {:?}",
                key
            );
        }
    }

    /// Invalidate a connection (due to error, GOAWAY, etc.)
    pub async fn invalidate(&self, key: &PoolKey) {
        let mut entries = self.entries.write().await;
        if let Some(entry) = entries.get_mut(key) {
            entry.invalidate();
        }
    }

    /// Remove expired and invalid connections
    pub async fn cleanup(&self) {
        // Cleanup H2/H3 entries
        {
            let mut entries = self.entries.write().await;
            entries
                .retain(|_key, entry| entry.is_valid && !entry.is_expired(self.max_idle_duration));
        }

        // Cleanup H1 entries
        {
            let mut h1_pool = self.h1_idle.write().await;
            for entries in h1_pool.values_mut() {
                entries.retain(|e| !e.is_expired(self.max_idle_duration));
            }
            h1_pool.retain(|_, entries| !entries.is_empty());
        }
    }

    /// Spawn a background cleanup task that runs periodically
    ///
    /// Returns a handle to the spawned task
    pub fn spawn_cleanup_task(self: Arc<Self>, interval: Duration) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);
            loop {
                interval_timer.tick().await;
                self.cleanup().await;
            }
        })
    }

    /// Get current pool statistics (for debugging/monitoring)
    pub async fn stats(&self) -> PoolStats {
        let entries = self.entries.read().await;
        let h1_pool = self.h1_idle.read().await;

        let h1_idle_count = h1_pool.values().map(|v| v.len()).sum();

        PoolStats {
            total_connections: entries.len() + h1_idle_count,
            active_streams: entries.values().map(|e| e.active_streams).sum(),
            http2_connections: entries
                .values()
                .filter(|e| matches!(e.version, HttpVersion::Http2))
                .count(),
            http3_connections: entries
                .values()
                .filter(|e| matches!(e.version, HttpVersion::Http3 | HttpVersion::Http3Only))
                .count(),
            http1_idle_connections: h1_idle_count,
        }
    }
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}

/// Pool statistics for monitoring
#[derive(Debug, Clone)]
pub struct PoolStats {
    pub total_connections: usize,
    pub active_streams: u32,
    pub http2_connections: usize,
    pub http3_connections: usize,
    pub http1_idle_connections: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_key_equality() {
        let key1 = PoolKey::new(
            "example.com".to_string(),
            443,
            true,
            FingerprintProfile::Chrome142,
            PseudoHeaderOrder::Chrome,
        );
        let key2 = PoolKey::new(
            "example.com".to_string(),
            443,
            true,
            FingerprintProfile::Chrome142,
            PseudoHeaderOrder::Chrome,
        );
        let key3 = PoolKey::new(
            "example.com".to_string(),
            80,
            false,
            FingerprintProfile::Chrome142,
            PseudoHeaderOrder::Chrome,
        );

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_pool_entry_multiplexing() {
        let mut entry = PoolEntry::new(HttpVersion::Http2, 100);

        // Should be able to acquire streams
        assert!(entry.can_multiplex());
        assert!(entry.acquire_stream());
        assert_eq!(entry.active_streams, 1);

        // Release stream
        entry.release_stream();
        assert_eq!(entry.active_streams, 0);
    }

    #[test]
    fn test_pool_entry_max_streams() {
        let mut entry = PoolEntry::new(HttpVersion::Http2, 2);

        assert!(entry.acquire_stream());
        assert!(entry.acquire_stream());
        assert!(!entry.acquire_stream()); // Max reached
        assert_eq!(entry.active_streams, 2);
    }

    #[test]
    fn test_pool_entry_invalidation() {
        let mut entry = PoolEntry::new(HttpVersion::Http2, 100);

        assert!(entry.can_multiplex());
        entry.invalidate();
        assert!(!entry.can_multiplex());
    }

    #[test]
    fn test_pool_entry_expiration() {
        let entry = PoolEntry::new(HttpVersion::Http2, 100);

        // Should not be expired immediately
        assert!(!entry.is_expired(Duration::from_secs(30)));

        // Test with zero duration (always expired)
        assert!(entry.is_expired(Duration::from_secs(0)));
    }

    #[tokio::test]
    async fn test_connection_pool_http11() {
        let pool = ConnectionPool::new();
        let key = PoolKey::new(
            "example.com".to_string(),
            443,
            true,
            FingerprintProfile::Chrome142,
            PseudoHeaderOrder::Chrome,
        );

        // HTTP/1.1 should always return None (no pooling)
        let result = pool
            .get_or_create(&key, HttpVersion::Http1_1)
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_connection_pool_http2_multiplexing() {
        let pool = ConnectionPool::new();
        let key = PoolKey::new(
            "example.com".to_string(),
            443,
            true,
            FingerprintProfile::Chrome142,
            PseudoHeaderOrder::Chrome,
        );

        // First request creates connection
        let entry1 = pool.get_or_create(&key, HttpVersion::Http2).await.unwrap();
        assert!(entry1.is_some());

        // Second request should reuse connection
        let entry2 = pool.get_or_create(&key, HttpVersion::Http2).await.unwrap();
        assert!(entry2.is_some());

        // Verify stats
        let stats = pool.stats().await;
        assert_eq!(stats.total_connections, 1);
        assert_eq!(stats.http2_connections, 1);
    }

    #[tokio::test]
    async fn test_connection_pool_release() {
        let pool = ConnectionPool::new();
        let key = PoolKey::new(
            "example.com".to_string(),
            443,
            true,
            FingerprintProfile::Chrome142,
            PseudoHeaderOrder::Chrome,
        );

        let _entry = pool.get_or_create(&key, HttpVersion::Http2).await.unwrap();

        // Release stream
        pool.release(&key).await;

        let stats = pool.stats().await;
        assert_eq!(stats.total_connections, 1);
    }

    #[tokio::test]
    async fn test_connection_pool_invalidation() {
        let pool = ConnectionPool::new();
        let key = PoolKey::new(
            "example.com".to_string(),
            443,
            true,
            FingerprintProfile::Chrome142,
            PseudoHeaderOrder::Chrome,
        );

        let _entry = pool.get_or_create(&key, HttpVersion::Http2).await.unwrap();

        // Invalidate connection
        pool.invalidate(&key).await;

        // Cleanup should remove invalid connection
        pool.cleanup().await;

        let stats = pool.stats().await;
        assert_eq!(stats.total_connections, 0);
    }
}
