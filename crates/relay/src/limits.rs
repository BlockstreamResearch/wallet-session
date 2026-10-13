use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use tokio::time::Instant;
use wallet_session_core::did::DidKey;

/// Maximum number of identities tracked by the connect rate limiter.
const MAX_RATE_KEYS: usize = 65_536;

/// Token-bucket parameters for connection attempts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimit {
    /// Maximum number of connection attempts available at once.
    pub burst: u32,

    /// Interval over which the burst refills.
    pub interval: Duration,
}

/// Static relay resource limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayLimitsConfig {
    /// Maximum concurrent connections across all identities.
    pub max_connections: usize,

    /// Maximum concurrent connections per identity.
    pub max_connections_per_identity: usize,

    /// Maximum concurrent sessions (topics).
    pub max_sessions: usize,

    /// Connection attempt rate per identity.
    pub connect_rate: RateLimit,
}

impl Default for RelayLimitsConfig {
    fn default() -> Self {
        Self {
            max_connections: 10_000,
            max_connections_per_identity: 16,
            max_sessions: 50_000,
            connect_rate: RateLimit {
                burst: 30,
                interval: Duration::from_secs(60),
            },
        }
    }
}

/// Lock a mutex, recovering the guard if it was poisoned.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// A token bucket for one identity.
#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

impl Bucket {
    fn full(burst: u32, now: Instant) -> Self {
        Self {
            tokens: f64::from(burst),
            last: now,
        }
    }

    /// Refill and consume one token, returning whether the attempt is allowed.
    fn allow(&mut self, rate: RateLimit, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last);
        let interval = rate.interval.as_secs_f64().max(f64::EPSILON);
        let refill = elapsed.as_secs_f64() / interval * f64::from(rate.burst);
        self.tokens = (self.tokens + refill).min(f64::from(rate.burst));
        self.last = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Shared runtime counters and rate limiters.
#[derive(Debug)]
pub struct Limiter {
    limits: RelayLimitsConfig,
    total: Mutex<usize>,
    per_identity: Mutex<HashMap<DidKey, usize>>,
    connect_rate: Mutex<HashMap<DidKey, Bucket>>,
}

impl Limiter {
    /// Build a limiter with the given static limits.
    pub fn new(limits: RelayLimitsConfig) -> Self {
        Self {
            limits,
            total: Mutex::new(0),
            per_identity: Mutex::new(HashMap::new()),
            connect_rate: Mutex::new(HashMap::new()),
        }
    }

    /// Static limits configured for this limiter.
    pub fn limits(&self) -> RelayLimitsConfig {
        self.limits
    }

    /// Maximum concurrent sessions, passed through to the registry.
    pub fn max_sessions(&self) -> usize {
        self.limits.max_sessions
    }

    /// Current number of connections holding a global slot.
    pub fn active_connections(&self) -> usize {
        *lock(&self.total)
    }

    /// Acquire a global connection slot, if capacity remains.
    pub fn acquire_total(self: &Arc<Self>) -> Option<ConnectionPermit> {
        let mut total = lock(&self.total);
        if *total >= self.limits.max_connections {
            return None;
        }
        *total += 1;
        drop(total);

        Some(ConnectionPermit {
            limiter: Arc::clone(self),
            identity: None,
        })
    }

    /// Acquire a per-identity connection slot, if capacity remains.
    pub fn acquire_identity(self: &Arc<Self>, identity: &DidKey) -> Option<ConnectionPermit> {
        let mut counts = lock(&self.per_identity);
        let count = counts.entry(identity.clone()).or_insert(0);
        if *count >= self.limits.max_connections_per_identity {
            return None;
        }
        *count += 1;
        drop(counts);

        Some(ConnectionPermit {
            limiter: Arc::clone(self),
            identity: Some(identity.clone()),
        })
    }

    /// Consume one connection-attempt token for `identity`.
    pub fn allow_connect(&self, identity: &DidKey) -> bool {
        self.allow_connect_at(identity, Instant::now())
    }

    fn allow_connect_at(&self, identity: &DidKey, now: Instant) -> bool {
        let rate = self.limits.connect_rate;
        let mut buckets = lock(&self.connect_rate);

        if buckets.len() >= MAX_RATE_KEYS {
            buckets.retain(|_, bucket| now.saturating_duration_since(bucket.last) < rate.interval);
            if buckets.len() >= MAX_RATE_KEYS
                && let Some(key) = buckets.keys().next().cloned()
            {
                buckets.remove(&key);
            }
        }

        let bucket = buckets
            .entry(identity.clone())
            .or_insert_with(|| Bucket::full(rate.burst, now));
        bucket.allow(rate, now)
    }
}

/// A held connection slot; released when dropped.
pub struct ConnectionPermit {
    limiter: Arc<Limiter>,
    identity: Option<DidKey>,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        if let Some(identity) = &self.identity {
            let mut counts = lock(&self.limiter.per_identity);
            if let Some(count) = counts.get_mut(identity) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    counts.remove(identity);
                }
            }
        }

        let mut total = lock(&self.limiter.total);
        *total = total.saturating_sub(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> DidKey {
        DidKey::from_ed25519_bytes([seed; 32])
    }

    fn limits() -> RelayLimitsConfig {
        RelayLimitsConfig {
            max_connections: 2,
            max_connections_per_identity: 1,
            max_sessions: 10,
            connect_rate: RateLimit {
                burst: 2,
                interval: Duration::from_secs(10),
            },
        }
    }

    #[test]
    fn identity_slot_is_released_on_drop() {
        let limiter = Arc::new(Limiter::new(limits()));
        let identity = key(1);

        let first = limiter.acquire_identity(&identity);
        assert!(first.is_some());
        assert!(limiter.acquire_identity(&identity).is_none());

        drop(first);
        assert!(limiter.acquire_identity(&identity).is_some());
    }

    #[test]
    fn total_slots_are_capped_across_identities() {
        let limiter = Arc::new(Limiter::new(limits()));

        let a = limiter.acquire_total();
        let b = limiter.acquire_total();
        assert!(a.is_some() && b.is_some());
        assert_eq!(limiter.active_connections(), 2);
        assert!(limiter.acquire_total().is_none());

        drop(a);
        assert_eq!(limiter.active_connections(), 1);
        assert!(limiter.acquire_total().is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn connect_rate_refills_over_time() {
        let limiter = Limiter::new(RelayLimitsConfig {
            connect_rate: RateLimit {
                burst: 1,
                interval: Duration::from_secs(10),
            },
            ..RelayLimitsConfig::default()
        });
        let identity = key(1);

        assert!(limiter.allow_connect(&identity));
        assert!(!limiter.allow_connect(&identity));

        tokio::time::advance(Duration::from_secs(10)).await;
        assert!(limiter.allow_connect(&identity));
    }
}
