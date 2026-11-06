//! Per-key replay memory for authenticated inbound envelopes.

use std::collections::HashMap;
use std::time::Duration;

use wallet_session_core::message::Message;

/// How a received envelope relates to the replay memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Observation {
    /// A new envelope: record it and deliver it.
    New,

    /// The identical envelope was already accepted: acknowledge it again,
    /// but do not deliver it again.
    Retransmission,

    /// An id or nonce was reused with different content.
    Conflict,
}

struct Record {
    message: Message,
    expires_at: u64,
}

/// Replay memory for one key.
///
/// A record is kept until the local clock passes the envelope's `ts` plus the
/// accepted clock-skew window. When a record expires, its `ts` is remembered,
/// so a clock that steps backward cannot make the discarded envelope
/// acceptable again.
pub(crate) struct ReplayMemory {
    retention_secs: u64,
    by_id: HashMap<String, Record>,
    by_nonce: HashMap<Vec<u8>, String>,
    largest_discarded_ts: Option<u64>,
}

impl ReplayMemory {
    /// Build an empty replay memory with the given timestamp retention window.
    pub(crate) fn new(retention: Duration) -> Self {
        Self {
            retention_secs: retention.as_secs(),
            by_id: HashMap::new(),
            by_nonce: HashMap::new(),
            largest_discarded_ts: None,
        }
    }

    /// Forget every record, for example when switching keys.
    pub(crate) fn clear(&mut self) {
        self.by_id.clear();
        self.by_nonce.clear();
        self.largest_discarded_ts = None;
    }

    /// Whether `ts` is at or below a timestamp already discarded from the
    /// replay memory.
    pub(crate) fn is_stale(&self, ts: u64) -> bool {
        self.largest_discarded_ts
            .is_some_and(|largest| ts <= largest)
    }

    /// Classify an authenticated envelope against the replay memory.
    ///
    /// `now` is the local Unix time, after the caller has checked `message.ts`
    /// against the clock-skew window. A [`Observation::New`] envelope is only
    /// remembered once the caller has delivered or acknowledged it, with
    /// [`ReplayMemory::record`].
    pub(crate) fn classify(&mut self, id: &str, message: &Message, now: u64) -> Observation {
        self.prune(now);

        if let Some(record) = self.by_id.get(id) {
            return if record.message == *message {
                Observation::Retransmission
            } else {
                log::debug!("replay conflict: frame {id} reused with different content");
                Observation::Conflict
            };
        }

        if let Some(owner) = self.by_nonce.get(message.nonce.as_bytes())
            && owner != id
        {
            log::debug!(
                "replay conflict: nonce {} used by frame {owner} and frame {id} \
                 (kind={:?}, from={}, ts={})",
                message.nonce,
                message.kind,
                message.from,
                message.ts
            );
            return Observation::Conflict;
        }

        Observation::New
    }

    /// Remember an envelope that was classified as [`Observation::New`].
    pub(crate) fn record(&mut self, id: &str, message: &Message) {
        self.by_nonce
            .insert(message.nonce.as_bytes().to_vec(), id.to_owned());
        self.by_id.insert(
            id.to_owned(),
            Record {
                message: message.clone(),
                expires_at: message.ts.saturating_add(self.retention_secs),
            },
        );
    }

    /// Forget an envelope that was recorded but then rejected before delivery.
    pub(crate) fn forget(&mut self, id: &str) {
        if let Some(record) = self.by_id.remove(id) {
            self.by_nonce.remove(record.message.nonce.as_bytes());
        }
    }

    /// Drop records whose expiry has passed and remember their timestamps.
    fn prune(&mut self, now: u64) {
        let expired: Vec<String> = self
            .by_id
            .iter()
            .filter(|(_, record)| record.expires_at < now)
            .map(|(id, _)| id.clone())
            .collect();

        for id in expired {
            if let Some(record) = self.by_id.remove(&id) {
                self.by_nonce.remove(record.message.nonce.as_bytes());
                self.largest_discarded_ts = Some(
                    self.largest_discarded_ts
                        .map_or(record.message.ts, |largest| largest.max(record.message.ts)),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wallet_session_core::{
        did::DidKey,
        message::{Ciphertext, MessageType, Nonce},
    };

    fn message_with_nonce(ts: u64, nonce: [u8; 24]) -> Message {
        Message::new(
            MessageType::Request,
            DidKey::from_ed25519_bytes([1u8; 32]),
            ts,
            Nonce::new(nonce.to_vec()).expect("nonce"),
            Ciphertext::new(vec![3, 4]),
        )
    }

    fn message(ts: u64) -> Message {
        message_with_nonce(ts, [2u8; 24])
    }

    fn nonce_with_counter(counter: u64) -> [u8; 24] {
        let mut nonce = [7u8; 24];
        nonce[16..].copy_from_slice(&counter.to_be_bytes());
        nonce
    }

    /// Classify and record, as the client does after delivering a message.
    fn observe(memory: &mut ReplayMemory, id: &str, message: &Message, now: u64) -> Observation {
        let observation = memory.classify(id, message, now);
        if observation == Observation::New {
            memory.record(id, message);
        }
        observation
    }

    #[test]
    fn classifies_retransmissions_and_conflicts() {
        let mut memory = ReplayMemory::new(Duration::from_secs(300));
        let original = message(1_000);

        assert_eq!(
            observe(&mut memory, "frame-1", &original, 1_000),
            Observation::New
        );
        assert_eq!(
            observe(&mut memory, "frame-1", &original, 1_000),
            Observation::Retransmission
        );

        let mut modified = original.clone();
        modified.data = Ciphertext::new(vec![9]);
        assert_eq!(
            observe(&mut memory, "frame-1", &modified, 1_000),
            Observation::Conflict
        );

        // The same nonce under a different frame id is also a conflict.
        assert_eq!(
            observe(&mut memory, "frame-2", &original, 1_000),
            Observation::Conflict
        );
    }

    #[test]
    fn accepts_unseen_nonces_regardless_of_counter_order() {
        let mut memory = ReplayMemory::new(Duration::from_secs(300));
        let later = message_with_nonce(1_000, nonce_with_counter(1));
        let earlier = message_with_nonce(1_000, nonce_with_counter(0));

        // A later counter is accepted first. An unseen earlier counter is not
        // a replay of it; counters only have to be unique per key.
        assert_eq!(
            observe(&mut memory, "frame-later", &later, 1_000),
            Observation::New
        );
        assert_eq!(
            observe(&mut memory, "frame-earlier", &earlier, 1_000),
            Observation::New
        );
    }

    #[test]
    fn expires_after_the_envelope_window() {
        let mut memory = ReplayMemory::new(Duration::from_secs(300));
        let original = message(1_000);

        assert_eq!(
            observe(&mut memory, "frame-1", &original, 1_000),
            Observation::New
        );
        assert_eq!(
            observe(&mut memory, "frame-1", &original, 1_300),
            Observation::Retransmission
        );

        // Pruning at 1_301 discards the record and remembers its timestamp.
        assert_eq!(
            observe(&mut memory, "frame-1", &original, 1_301),
            Observation::New
        );
        assert!(memory.is_stale(1_000));
        assert!(!memory.is_stale(1_001));
    }

    #[test]
    fn discarded_timestamp_outlives_the_record() {
        let mut memory = ReplayMemory::new(Duration::from_secs(300));
        let original = message(1_000);

        observe(&mut memory, "frame-1", &original, 1_000);
        let mut later = message(1_001);
        later.nonce = Nonce::new([3u8; 24]).expect("nonce");
        observe(&mut memory, "frame-2", &later, 1_301);

        // The record is gone, but a copy replayed after a clock rollback is
        // still rejected by the remembered discarded timestamp.
        assert!(memory.is_stale(original.ts));
    }

    #[test]
    fn clear_drops_records_and_discarded_timestamps() {
        let mut memory = ReplayMemory::new(Duration::from_secs(300));
        let original = message(1_000);

        observe(&mut memory, "frame-1", &original, 1_000);
        observe(&mut memory, "frame-2", &message(1_001), 1_301);
        memory.clear();

        assert!(!memory.is_stale(1_000));
        assert_eq!(
            observe(&mut memory, "frame-1", &original, 1_000),
            Observation::New
        );
    }
}
