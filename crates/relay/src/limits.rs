use std::{
    collections::HashMap,
    hash::Hash,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use tokio::time::Instant;
use wallet_session_core::did::DidKey;

use crate::source::Source;

/// Maximum number of identities or sources tracked by one keyed rate limiter.
const MAX_RATE_KEYS: usize = 65_536;

/// Token-bucket parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimit {
    /// Maximum cost (attempts, messages or bytes) available at once.
    pub burst: u32,

    /// Interval over which the burst refills.
    pub interval: Duration,
}

/// Outcome of charging the relay-wide inbound byte budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundBytes {
    /// Accepted against the identity and source shares and the global budget.
    Allowed,

    /// The identity already consumed its share of the budget.
    ShareExhausted,

    /// The identity is within its share, but the identities connecting from
    /// its source address have together consumed the source's share.
    SourceExhausted,

    /// Both shares have room, but the global budget is dry, or down to the
    /// reserve for paired traffic.
    GlobalExhausted,
}

/// What the inbound bytes being charged are for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Traffic {
    /// Frames between two connected peers. They may spend the whole relay-wide
    /// budget, the share reserved for them included.
    Paired,

    /// Anything else the relay spends work on: frames buffered for a peer
    /// that is reconnecting, and control frames on a connection whose
    /// counterpart is not connected. They are refused once the relay-wide
    /// budget is down to the paired reserve.
    Unpaired,
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

    /// Inbound message rate per connection.
    pub inbound_message_rate: RateLimit,

    /// Inbound byte rate per connection.
    pub inbound_byte_rate: RateLimit,

    /// Inbound byte rate one identity may consume from the relay-wide budget.
    /// Sized so that several identities together can exhaust
    /// [`RelayLimitsConfig::global_inbound_byte_rate`], but one cannot.
    pub identity_inbound_byte_rate: RateLimit,

    /// Inbound byte rate the identities connecting from one source address
    /// may consume together from the relay-wide budget. Identities cost
    /// nothing to mint and addresses do, so this is what bounds one client
    /// spreading its traffic across many identities. No larger than the
    /// identity share by default.
    pub source_inbound_byte_rate: RateLimit,

    /// Inbound byte rate across all connections.
    pub global_inbound_byte_rate: RateLimit,

    /// Percentage of the global burst that only [`Traffic::Paired`] bytes may
    /// spend, so that one-sided sessions cannot take the last of the budget
    /// from peers that are talking to each other.
    pub global_paired_reserve_percent: u8,
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
            inbound_message_rate: RateLimit {
                burst: 32,
                interval: Duration::from_secs(2),
            },
            inbound_byte_rate: RateLimit {
                burst: 512 * 1024,
                interval: Duration::from_secs(2),
            },
            identity_inbound_byte_rate: RateLimit {
                burst: 1024 * 1024,
                interval: Duration::from_secs(1),
            },
            source_inbound_byte_rate: RateLimit {
                burst: 1024 * 1024,
                interval: Duration::from_secs(1),
            },
            global_inbound_byte_rate: RateLimit {
                burst: 16 * 1024 * 1024,
                interval: Duration::from_secs(1),
            },
            global_paired_reserve_percent: 25,
        }
    }
}

impl RelayLimitsConfig {
    /// Bytes of the global burst only [`Traffic::Paired`] bytes may spend.
    pub fn paired_reserve_bytes(&self) -> u32 {
        let percent = u64::from(self.global_paired_reserve_percent.min(100));
        let reserve = u64::from(self.global_inbound_byte_rate.burst) * percent / 100;
        u32::try_from(reserve).unwrap_or(u32::MAX)
    }
}

/// Lock a mutex, recovering the guard if it was poisoned.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// A token bucket.
#[derive(Debug)]
pub(crate) struct Bucket {
    tokens: f64,
    last: Instant,
}

impl Bucket {
    pub(crate) fn full(burst: u32, now: Instant) -> Self {
        Self {
            tokens: f64::from(burst),
            last: now,
        }
    }

    /// Refill and consume one token, returning whether the attempt is allowed.
    fn allow(&mut self, rate: RateLimit, now: Instant) -> bool {
        self.allow_n(1, rate, now)
    }

    /// Return tokens that were charged but not spent.
    pub(crate) fn refund(&mut self, cost: u32, rate: RateLimit) {
        let cost = cost.clamp(1, rate.burst.max(1));
        self.tokens = (self.tokens + f64::from(cost)).min(f64::from(rate.burst));
    }

    /// Refill and consume `cost` tokens, returning whether the attempt is allowed.
    pub(crate) fn allow_n(&mut self, cost: u32, rate: RateLimit, now: Instant) -> bool {
        self.allow_n_above(cost, 0, rate, now)
    }

    /// Refill and consume `cost` tokens if at least `floor` remain afterwards,
    /// returning whether the attempt is allowed.
    fn allow_n_above(&mut self, cost: u32, floor: u32, rate: RateLimit, now: Instant) -> bool {
        let cost = f64::from(cost.clamp(1, rate.burst.max(1)));
        let elapsed = now.saturating_duration_since(self.last);
        let interval = rate.interval.as_secs_f64().max(f64::EPSILON);
        let refill = elapsed.as_secs_f64() / interval * f64::from(rate.burst);
        self.tokens = (self.tokens + refill).min(f64::from(rate.burst));
        self.last = now;

        if self.tokens - cost >= f64::from(floor) {
            self.tokens -= cost;
            true
        } else {
            false
        }
    }
}

/// Per-key token buckets, with the time of the last full prune.
#[derive(Debug)]
struct BucketMap<K> {
    buckets: HashMap<K, Bucket>,
    last_prune: Instant,
}

impl<K> BucketMap<K> {
    fn new(now: Instant) -> Self {
        Self {
            buckets: HashMap::new(),
            last_prune: now,
        }
    }
}

fn bucket_for<'a, K: Eq + Hash + Clone>(
    state: &'a mut BucketMap<K>,
    key: &K,
    rate: RateLimit,
    now: Instant,
) -> &'a mut Bucket {
    if state.buckets.len() >= MAX_RATE_KEYS {
        if now.saturating_duration_since(state.last_prune) >= rate.interval {
            state
                .buckets
                .retain(|_, bucket| now.saturating_duration_since(bucket.last) < rate.interval);
            state.last_prune = now;
        }
        while state.buckets.len() >= MAX_RATE_KEYS {
            let Some(evicted) = state.buckets.keys().next().cloned() else {
                break;
            };
            state.buckets.remove(&evicted);
        }
    }
    state
        .buckets
        .entry(key.clone())
        .or_insert_with(|| Bucket::full(rate.burst, now))
}

/// Shared runtime counters and rate limiters.
#[derive(Debug)]
pub struct Limiter {
    limits: RelayLimitsConfig,
    total: Mutex<usize>,
    per_identity: Mutex<HashMap<DidKey, usize>>,
    connect_rate: Mutex<BucketMap<DidKey>>,
    identity_bytes: Mutex<BucketMap<DidKey>>,
    source_bytes: Mutex<BucketMap<Source>>,
    inbound_bytes: Mutex<Bucket>,
    dropped_share_bytes: AtomicU64,
    dropped_source_bytes: AtomicU64,
    dropped_global_bytes: AtomicU64,
}

impl Limiter {
    /// Build a limiter with the given static limits.
    pub fn new(limits: RelayLimitsConfig) -> Self {
        let now = Instant::now();
        Self {
            limits,
            total: Mutex::new(0),
            per_identity: Mutex::new(HashMap::new()),
            connect_rate: Mutex::new(BucketMap::new(now)),
            identity_bytes: Mutex::new(BucketMap::new(now)),
            source_bytes: Mutex::new(BucketMap::new(now)),
            inbound_bytes: Mutex::new(Bucket::full(limits.global_inbound_byte_rate.burst, now)),
            dropped_share_bytes: AtomicU64::new(0),
            dropped_source_bytes: AtomicU64::new(0),
            dropped_global_bytes: AtomicU64::new(0),
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

    /// Consume `bytes` sent by `identity` from `source` from the identity's
    /// and the source's shares of the relay-wide budget, and from the budget
    /// itself.
    ///
    /// The identity share is checked first, so a sender over its own share
    /// hears so even when its source is exhausted as well. Nothing is spent
    /// unless every budget has room: a refused charge is given back to the
    /// shares that had already accepted it. [`Traffic::Unpaired`] bytes are
    /// refused once the global budget is down to the paired reserve.
    pub fn allow_inbound_bytes(
        &self,
        identity: &DidKey,
        source: &Source,
        bytes: usize,
        traffic: Traffic,
    ) -> InboundBytes {
        let cost = u32::try_from(bytes).unwrap_or(u32::MAX);
        let now = Instant::now();
        let share = self.limits.identity_inbound_byte_rate;
        let source_share = self.limits.source_inbound_byte_rate;

        if cost > share.burst {
            self.dropped_share_bytes
                .fetch_add(u64::from(cost), Ordering::Relaxed);
            return InboundBytes::ShareExhausted;
        }

        // Locks are always taken in this order: identities, sources, global.
        let mut identities = lock(&self.identity_bytes);
        let identity_bucket = bucket_for(&mut identities, identity, share, now);
        if !identity_bucket.allow_n(cost, share, now) {
            self.dropped_share_bytes
                .fetch_add(u64::from(cost), Ordering::Relaxed);
            return InboundBytes::ShareExhausted;
        }

        let mut sources = lock(&self.source_bytes);
        let source_bucket = bucket_for(&mut sources, source, source_share, now);
        // A cost above the burst would be charged as only the burst.
        if cost > source_share.burst || !source_bucket.allow_n(cost, source_share, now) {
            identity_bucket.refund(cost, share);
            self.dropped_source_bytes
                .fetch_add(u64::from(cost), Ordering::Relaxed);
            return InboundBytes::SourceExhausted;
        }

        let floor = match traffic {
            Traffic::Paired => 0,
            Traffic::Unpaired => self.limits.paired_reserve_bytes(),
        };
        let within_global = lock(&self.inbound_bytes).allow_n_above(
            cost,
            floor,
            self.limits.global_inbound_byte_rate,
            now,
        );
        if !within_global {
            identity_bucket.refund(cost, share);
            source_bucket.refund(cost, source_share);
            self.dropped_global_bytes
                .fetch_add(u64::from(cost), Ordering::Relaxed);
            return InboundBytes::GlobalExhausted;
        }
        InboundBytes::Allowed
    }

    /// Bytes dropped because a sender exceeded its identity's share.
    pub fn dropped_share_bytes(&self) -> u64 {
        self.dropped_share_bytes.load(Ordering::Relaxed)
    }

    /// Bytes dropped because the identities behind one source address
    /// exceeded the source's share.
    pub fn dropped_source_bytes(&self) -> u64 {
        self.dropped_source_bytes.load(Ordering::Relaxed)
    }

    /// Bytes dropped because the relay-wide budget was exhausted.
    pub fn dropped_global_bytes(&self) -> u64 {
        self.dropped_global_bytes.load(Ordering::Relaxed)
    }

    /// Consume one connection-attempt token for `identity`.
    pub fn allow_connect(&self, identity: &DidKey) -> bool {
        self.allow_connect_at(identity, Instant::now())
    }

    fn allow_connect_at(&self, identity: &DidKey, now: Instant) -> bool {
        let rate = self.limits.connect_rate;
        let mut state = lock(&self.connect_rate);
        bucket_for(&mut state, identity, rate, now).allow(rate, now)
    }

    /// Number of identities the connect limiter is tracking.
    #[cfg(test)]
    fn tracked_identities(&self) -> usize {
        lock(&self.connect_rate).buckets.len()
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
        } else {
            let mut total = lock(&self.limiter.total);
            *total = total.saturating_sub(1);
        }
    }
}

/// Bytes of frames held for one peer and not yet written to it.
///
/// A connection's budget covers its outbound queue, the frame its writer is
/// writing, and the backlog waiting to enter the queue; a reserved slot has
/// one of its own for the frames buffered while its peer reconnects. Bytes
/// are the frame's JSON text, which is what the writer sends.
#[derive(Debug)]
pub struct OutboundBudget {
    capacity: usize,
    held: AtomicUsize,
}

impl OutboundBudget {
    /// An empty budget of `capacity` bytes.
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            held: AtomicUsize::new(0),
        }
    }

    /// Bytes this budget may hold at once.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Bytes currently charged to this budget.
    pub fn held(&self) -> usize {
        self.held.load(Ordering::Relaxed)
    }

    /// Charge `bytes`, if they fit beside what is already held.
    pub(crate) fn try_charge(self: &Arc<Self>, bytes: usize) -> Option<OutboundCharge> {
        self.held
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |held| {
                held.checked_add(bytes)
                    .filter(|total| *total <= self.capacity)
            })
            .ok()?;
        Some(OutboundCharge {
            budget: Arc::clone(self),
            bytes,
        })
    }
}

/// Bytes charged to an [`OutboundBudget`]; given back when dropped.
#[derive(Debug)]
pub(crate) struct OutboundCharge {
    budget: Arc<OutboundBudget>,
    bytes: usize,
}

impl OutboundCharge {
    /// Bytes this charge holds.
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }
}

impl Drop for OutboundCharge {
    fn drop(&mut self) {
        self.budget.held.fetch_sub(self.bytes, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::IpAddr;

    fn key(seed: u8) -> DidKey {
        DidKey::from_ed25519_bytes([seed; 32])
    }

    /// A source address of its own for each `seed`.
    fn source(seed: u8) -> Source {
        Source::of(IpAddr::from([192, 0, 2, seed]))
    }

    /// Charge paired bytes from the source the tests share unless they say
    /// otherwise.
    fn paired(limiter: &Limiter, identity: &DidKey, bytes: usize) -> InboundBytes {
        limiter.allow_inbound_bytes(identity, &source(1), bytes, Traffic::Paired)
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
            ..RelayLimitsConfig::default()
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

    #[tokio::test(start_paused = true)]
    async fn bucket_charges_cost_and_refills() {
        let rate = RateLimit {
            burst: 100,
            interval: Duration::from_secs(10),
        };
        let mut bucket = Bucket::full(rate.burst, Instant::now());

        assert!(bucket.allow_n(60, rate, Instant::now()));
        assert!(!bucket.allow_n(60, rate, Instant::now()));
        assert!(bucket.allow_n(40, rate, Instant::now()));

        // 10 tokens per second.
        tokio::time::advance(Duration::from_secs(3)).await;
        assert!(!bucket.allow_n(31, rate, Instant::now()));
        assert!(bucket.allow_n(30, rate, Instant::now()));
    }

    #[tokio::test(start_paused = true)]
    async fn oversized_cost_is_clamped_to_burst() {
        let rate = RateLimit {
            burst: 100,
            interval: Duration::from_secs(10),
        };
        let mut bucket = Bucket::full(rate.burst, Instant::now());

        assert!(bucket.allow_n(1_000, rate, Instant::now()));
        assert!(!bucket.allow_n(1, rate, Instant::now()));
    }

    #[tokio::test(start_paused = true)]
    async fn zero_burst_denies_everything() {
        let rate = RateLimit {
            burst: 0,
            interval: Duration::from_secs(10),
        };
        let mut bucket = Bucket::full(rate.burst, Instant::now());
        assert!(!bucket.allow_n(1, rate, Instant::now()));
    }

    fn key_from_u32(value: u32) -> DidKey {
        let mut bytes = [0u8; 32];
        bytes[..4].copy_from_slice(&value.to_le_bytes());
        DidKey::from_ed25519_bytes(bytes)
    }

    #[tokio::test(start_paused = true)]
    async fn connect_rate_map_stays_bounded() {
        let limiter = Limiter::new(RelayLimitsConfig::default());

        for seed in 0..MAX_RATE_KEYS as u32 + 128 {
            limiter.allow_connect(&key_from_u32(seed));
        }

        assert!(limiter.tracked_identities() <= MAX_RATE_KEYS);
        // A fresh identity can still attempt a connection.
        assert!(limiter.allow_connect(&key_from_u32(u32::MAX)));
    }

    #[tokio::test(start_paused = true)]
    async fn connect_rate_prunes_stale_identities() {
        let interval = Duration::from_secs(10);
        let limiter = Limiter::new(RelayLimitsConfig {
            connect_rate: RateLimit { burst: 1, interval },
            ..RelayLimitsConfig::default()
        });

        for seed in 0..MAX_RATE_KEYS as u32 {
            limiter.allow_connect(&key_from_u32(seed));
        }
        assert_eq!(limiter.tracked_identities(), MAX_RATE_KEYS);

        tokio::time::advance(interval + Duration::from_secs(1)).await;
        assert!(limiter.allow_connect(&key_from_u32(u32::MAX)));
        assert_eq!(
            limiter.tracked_identities(),
            1,
            "stale buckets are pruned once the interval has passed"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn global_inbound_bytes_are_shared_and_refill() {
        let limiter = Limiter::new(RelayLimitsConfig {
            identity_inbound_byte_rate: RateLimit {
                burst: 100_000,
                interval: Duration::from_secs(60),
            },
            global_inbound_byte_rate: RateLimit {
                burst: 1_000,
                interval: Duration::from_secs(10),
            },
            ..RelayLimitsConfig::default()
        });
        let identity = key(1);

        assert_eq!(paired(&limiter, &identity, 600), InboundBytes::Allowed);
        assert_eq!(
            paired(&limiter, &identity, 600),
            InboundBytes::GlobalExhausted
        );
        assert_eq!(paired(&limiter, &identity, 400), InboundBytes::Allowed);

        tokio::time::advance(Duration::from_secs(10)).await;
        assert_eq!(paired(&limiter, &identity, 1_000), InboundBytes::Allowed);
        assert_eq!(limiter.dropped_global_bytes(), 600);
        assert_eq!(limiter.dropped_share_bytes(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn an_identity_cannot_exhaust_the_global_budget() {
        let limiter = Limiter::new(RelayLimitsConfig {
            identity_inbound_byte_rate: RateLimit {
                burst: 100,
                interval: Duration::from_secs(60),
            },
            global_inbound_byte_rate: RateLimit {
                burst: 1_000_000,
                interval: Duration::from_secs(60),
            },
            ..RelayLimitsConfig::default()
        });
        let hog = key(1);
        let other = key(2);

        assert_eq!(paired(&limiter, &hog, 100), InboundBytes::Allowed);
        assert_eq!(paired(&limiter, &hog, 1), InboundBytes::ShareExhausted);

        assert_eq!(
            paired(&limiter, &other, 100),
            InboundBytes::Allowed,
            "another identity keeps its own share"
        );
        assert_eq!(limiter.dropped_share_bytes(), 1);
        assert_eq!(limiter.dropped_global_bytes(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn the_share_enforces_its_burst_and_survives_global_rejections() {
        let limiter = Limiter::new(RelayLimitsConfig {
            identity_inbound_byte_rate: RateLimit {
                burst: 4,
                interval: Duration::from_secs(3600),
            },
            global_inbound_byte_rate: RateLimit {
                burst: 4,
                interval: Duration::from_secs(1),
            },
            ..RelayLimitsConfig::default()
        });
        let hog = key(1);
        let other = key(2);
        let oversized = key(3);

        assert_eq!(paired(&limiter, &hog, 4), InboundBytes::Allowed);
        assert_eq!(paired(&limiter, &other, 4), InboundBytes::GlobalExhausted);
        assert_eq!(limiter.dropped_global_bytes(), 4);
        assert_eq!(limiter.dropped_share_bytes(), 0);

        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(
            paired(&limiter, &other, 4),
            InboundBytes::Allowed,
            "a globally rejected frame must not spend the identity share"
        );

        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(
            paired(&limiter, &oversized, 5),
            InboundBytes::ShareExhausted,
            "a frame larger than the share burst can never fit it"
        );
        assert_eq!(limiter.dropped_share_bytes(), 5);
        assert_eq!(
            paired(&limiter, &oversized, 4),
            InboundBytes::Allowed,
            "the rejected oversized frame must not have spent the share"
        );
    }

    #[test]
    fn outbound_budget_refuses_what_does_not_fit_and_takes_back_on_drop() {
        let budget = Arc::new(OutboundBudget::new(100));

        let first = budget.try_charge(60);
        assert!(first.is_some());
        assert!(
            budget.try_charge(41).is_none(),
            "a charge must fit beside what is held"
        );
        let second = budget.try_charge(40);
        assert!(second.is_some(), "a charge may fill the budget exactly");
        assert_eq!(budget.held(), 100);

        drop(first);
        assert_eq!(budget.held(), 40, "a dropped charge gives its bytes back");
        assert!(budget.try_charge(60).is_some());
        assert_eq!(budget.held(), 40, "an unbound charge is given back at once");
    }

    #[test]
    fn outbound_budget_refuses_a_charge_larger_than_itself() {
        let budget = Arc::new(OutboundBudget::new(100));
        assert!(budget.try_charge(101).is_none());
        assert!(budget.try_charge(usize::MAX).is_none());

        let _held = budget.try_charge(1);
        assert!(
            budget.try_charge(usize::MAX).is_none(),
            "an overflowing total must be refused, not wrapped"
        );
        assert_eq!(budget.held(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn the_global_budget_still_caps_the_sum_of_shares() {
        let limiter = Limiter::new(RelayLimitsConfig {
            identity_inbound_byte_rate: RateLimit {
                burst: 1_000,
                interval: Duration::from_secs(60),
            },
            global_inbound_byte_rate: RateLimit {
                burst: 1_500,
                interval: Duration::from_secs(60),
            },
            ..RelayLimitsConfig::default()
        });

        assert_eq!(paired(&limiter, &key(1), 1_000), InboundBytes::Allowed);
        assert_eq!(
            paired(&limiter, &key(2), 1_000),
            InboundBytes::GlobalExhausted
        );
        assert_eq!(limiter.dropped_global_bytes(), 1_000);
    }

    #[tokio::test(start_paused = true)]
    async fn a_source_share_caps_the_identities_behind_one_address() {
        let roomy = RateLimit {
            burst: 1_000_000,
            interval: Duration::from_secs(60),
        };
        let limiter = Limiter::new(RelayLimitsConfig {
            identity_inbound_byte_rate: roomy,
            source_inbound_byte_rate: RateLimit {
                burst: 1_000,
                interval: Duration::from_secs(60),
            },
            global_inbound_byte_rate: roomy,
            ..RelayLimitsConfig::default()
        });

        // Fresh identities from one address spend one share between them.
        for seed in 1..=4 {
            assert_eq!(
                limiter.allow_inbound_bytes(&key(seed), &source(1), 250, Traffic::Paired),
                InboundBytes::Allowed
            );
        }
        assert_eq!(
            limiter.allow_inbound_bytes(&key(5), &source(1), 1, Traffic::Paired),
            InboundBytes::SourceExhausted,
            "a fifth identity from the same address finds the share spent"
        );
        assert_eq!(limiter.dropped_source_bytes(), 1);
        assert_eq!(limiter.dropped_share_bytes(), 0);
        assert_eq!(limiter.dropped_global_bytes(), 0);

        assert_eq!(
            limiter.allow_inbound_bytes(&key(1), &source(2), 1_000, Traffic::Paired),
            InboundBytes::Allowed,
            "another address keeps its own share, whichever identity uses it"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_source_refusal_spends_no_identity_share() {
        let limiter = Limiter::new(RelayLimitsConfig {
            identity_inbound_byte_rate: RateLimit {
                burst: 200,
                interval: Duration::from_secs(3600),
            },
            source_inbound_byte_rate: RateLimit {
                burst: 100,
                interval: Duration::from_secs(3600),
            },
            ..RelayLimitsConfig::default()
        });

        assert_eq!(
            limiter.allow_inbound_bytes(&key(1), &source(1), 100, Traffic::Paired),
            InboundBytes::Allowed
        );
        assert_eq!(
            limiter.allow_inbound_bytes(&key(2), &source(1), 100, Traffic::Paired),
            InboundBytes::SourceExhausted
        );
        assert_eq!(
            limiter.allow_inbound_bytes(&key(2), &source(2), 100, Traffic::Paired),
            InboundBytes::Allowed,
            "the refused frame must not have spent the identity share"
        );

        assert_eq!(
            limiter.allow_inbound_bytes(&key(3), &source(3), 150, Traffic::Paired),
            InboundBytes::SourceExhausted,
            "a frame larger than the source burst can never fit it"
        );
        assert_eq!(
            limiter.allow_inbound_bytes(&key(3), &source(3), 100, Traffic::Paired),
            InboundBytes::Allowed,
            "the oversized frame must have spent neither share"
        );
        assert_eq!(limiter.dropped_source_bytes(), 250);
    }

    #[tokio::test(start_paused = true)]
    async fn unpaired_bytes_cannot_spend_the_paired_reserve() {
        let roomy = RateLimit {
            burst: 1_000_000,
            interval: Duration::from_secs(60),
        };
        let limiter = Limiter::new(RelayLimitsConfig {
            identity_inbound_byte_rate: roomy,
            source_inbound_byte_rate: roomy,
            global_inbound_byte_rate: RateLimit {
                burst: 1_000,
                interval: Duration::from_secs(3600),
            },
            global_paired_reserve_percent: 25,
            ..RelayLimitsConfig::default()
        });

        // However many identities and addresses one-sided traffic comes
        // from, it stops where the reserve begins.
        for seed in 1..=3 {
            assert_eq!(
                limiter.allow_inbound_bytes(&key(seed), &source(seed), 250, Traffic::Unpaired),
                InboundBytes::Allowed
            );
        }
        assert_eq!(
            limiter.allow_inbound_bytes(&key(4), &source(4), 1, Traffic::Unpaired),
            InboundBytes::GlobalExhausted
        );
        assert_eq!(limiter.dropped_global_bytes(), 1);

        assert_eq!(
            limiter.allow_inbound_bytes(&key(5), &source(5), 250, Traffic::Paired),
            InboundBytes::Allowed,
            "paired traffic still has the reserve"
        );
        assert_eq!(
            limiter.allow_inbound_bytes(&key(5), &source(5), 1, Traffic::Paired),
            InboundBytes::GlobalExhausted
        );
    }

    #[test]
    fn the_paired_reserve_is_a_share_of_the_global_burst() {
        let mut limits = RelayLimitsConfig::default();
        assert_eq!(limits.paired_reserve_bytes(), 4 * 1024 * 1024);

        limits.global_paired_reserve_percent = 0;
        assert_eq!(limits.paired_reserve_bytes(), 0);

        limits.global_inbound_byte_rate.burst = u32::MAX;
        limits.global_paired_reserve_percent = 99;
        assert_eq!(limits.paired_reserve_bytes(), 4_252_017_622);
    }
}
