//! DNS resolution hooks and lightweight caching for Specter transports.

use crate::error::{Error, Result};
use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

pub type ResolveFuture<'a> = Pin<Box<dyn Future<Output = Result<Vec<SocketAddr>>> + Send + 'a>>;

/// Async DNS resolver hook used by `ClientBuilder::dns_resolver`.
pub trait Resolve: Send + Sync {
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> ResolveFuture<'a>;
}

#[derive(Clone)]
pub struct DnsConfig {
    overrides: Arc<HashMap<String, Vec<SocketAddr>>>,
    resolver: Arc<dyn Resolve>,
    cache: Arc<RwLock<HashMap<(String, u16), DnsCacheEntry>>>,
    cache_enabled: bool,
    cache_ttl: Duration,
}

impl fmt::Debug for DnsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsConfig")
            .field("overrides", &self.overrides.keys().collect::<Vec<_>>())
            .field("cache_enabled", &self.cache_enabled)
            .field("cache_ttl", &self.cache_ttl)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
struct DnsCacheEntry {
    resolved_at: Instant,
    addrs: Vec<SocketAddr>,
}

impl DnsConfig {
    pub fn new() -> Self {
        Self {
            overrides: Arc::new(HashMap::new()),
            resolver: Arc::new(SystemResolver),
            cache: Arc::new(RwLock::new(HashMap::new())),
            cache_enabled: true,
            cache_ttl: Duration::from_secs(300),
        }
    }

    pub fn with_override(mut self, domain: &str, addrs: Vec<SocketAddr>) -> Self {
        let mut overrides = (*self.overrides).clone();
        overrides.insert(normalize_domain(domain), addrs);
        self.overrides = Arc::new(overrides);
        self
    }

    pub fn with_resolver(mut self, resolver: Arc<dyn Resolve>) -> Self {
        self.resolver = resolver;
        self
    }

    pub fn with_cache_enabled(mut self, enabled: bool) -> Self {
        self.cache_enabled = enabled;
        self
    }

    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        self
    }

    pub async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        let key = (normalize_domain(host), port);
        if let Some(addrs) = self.overrides.get(&key.0) {
            return Ok(addrs.clone());
        }

        if self.cache_enabled {
            if let Some(entry) = self.cache.read().await.get(&key).cloned() {
                if entry.resolved_at.elapsed() < self.cache_ttl {
                    return Ok(entry.addrs);
                }
            }
        }

        let addrs = self.resolver.resolve(host, port).await?;
        if addrs.is_empty() {
            return Err(Error::Connection(format!(
                "No addresses found for {host}:{port}"
            )));
        }
        if self.cache_enabled {
            self.cache.write().await.insert(
                key,
                DnsCacheEntry {
                    resolved_at: Instant::now(),
                    addrs: addrs.clone(),
                },
            );
        }
        Ok(addrs)
    }
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self::new()
    }
}

struct SystemResolver;

impl Resolve for SystemResolver {
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> ResolveFuture<'a> {
        Box::pin(async move {
            tokio::net::lookup_host((host, port))
                .await
                .map_err(|e| {
                    Error::Connection(format!("DNS resolution failed for {host}:{port}: {e}"))
                })
                .map(|iter| iter.collect())
        })
    }
}

fn normalize_domain(domain: &str) -> String {
    domain.trim_end_matches('.').to_ascii_lowercase()
}
