use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::{
    sync::mpsc,
    task::JoinHandle,
    time::{Instant, interval},
};
use wallet_session_core::{frame::RelayFrame, message::MessageType};

use crate::{error::ClientError, relay::Outbound};

/// Reliability events surfaced to the application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientEvent {
    /// A sent message was acknowledged by the peer.
    Delivered {
        /// Envelope id that was acknowledged.
        id: String,
    },

    /// A sent message exhausted its retransmissions.
    Failed {
        /// Envelope id that never got acknowledged.
        id: String,

        /// Retransmissions attempted.
        attempts: usize,
    },
}

/// Whether a message type must be acknowledged.
pub(crate) fn requires_ack(kind: MessageType) -> bool {
    matches!(
        kind,
        MessageType::Proposal
            | MessageType::Approve
            | MessageType::Reject
            | MessageType::Request
            | MessageType::Response
            | MessageType::Disconnect
            | MessageType::SessionDelete
    )
}

struct Pending {
    frame: RelayFrame,
    attempts: usize,
    next: Instant,
}

/// Rolling set of recently seen envelope ids, for duplicate suppression.
struct SeenIds {
    ttl: Duration,
    seen: HashMap<String, Instant>,
}

impl SeenIds {
    fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            seen: HashMap::new(),
        }
    }

    /// Record `id`, returning true if it was already seen within the TTL.
    fn observe(&mut self, id: &str) -> bool {
        let now = Instant::now();
        self.seen
            .retain(|_, seen_at| now.duration_since(*seen_at) < self.ttl);

        if self.seen.contains_key(id) {
            true
        } else {
            self.seen.insert(id.to_owned(), now);
            false
        }
    }
}

/// Outbound reliability: ack tracking, retransmission, and inbound dedupe.
pub(crate) struct Reliability {
    outbox: mpsc::UnboundedSender<Outbound>,
    pending: Arc<Mutex<HashMap<String, Pending>>>,
    seen: SeenIds,
    events: mpsc::UnboundedSender<ClientEvent>,
    base_delay: Duration,
    _retry: JoinHandle<()>,
}

impl Reliability {
    pub(crate) fn spawn(
        outbox: mpsc::UnboundedSender<Outbound>,
        base_delay: Duration,
        max_attempts: usize,
        seen_ttl: Duration,
    ) -> (Self, mpsc::UnboundedReceiver<ClientEvent>) {
        let pending = Arc::new(Mutex::new(HashMap::new()));
        let (events, events_rx) = mpsc::unbounded_channel();
        let _retry = tokio::spawn(retry_loop(
            Arc::clone(&pending),
            outbox.clone(),
            events.clone(),
            base_delay,
            max_attempts,
        ));

        (
            Self {
                outbox,
                pending,
                seen: SeenIds::new(seen_ttl),
                events,
                base_delay,
                _retry,
            },
            events_rx,
        )
    }

    /// Enqueue a frame, tracking it for retransmission when `track` is set.
    pub(crate) fn dispatch(&mut self, frame: RelayFrame, track: bool) -> Result<(), ClientError> {
        if track {
            let pending = Pending {
                frame: frame.clone(),
                attempts: 0,
                next: Instant::now() + self.base_delay,
            };
            self.pending
                .lock()
                .expect("reliability lock")
                .insert(frame.id.clone(), pending);
        }

        self.outbox
            .send(Outbound::Frame(frame))
            .map_err(|_| ClientError::Closed)
    }

    /// Record an inbound ACK, reporting delivery.
    pub(crate) fn mark_delivered(&mut self, ack_id: &str) {
        if self
            .pending
            .lock()
            .expect("reliability lock")
            .remove(ack_id)
            .is_some()
        {
            let _ = self.events.send(ClientEvent::Delivered {
                id: ack_id.to_owned(),
            });
        }
    }

    /// Returns true if the frame id was already seen recently.
    pub(crate) fn is_duplicate(&mut self, id: &str) -> bool {
        self.seen.observe(id)
    }
}

impl Drop for Reliability {
    fn drop(&mut self) {
        // Stop the retry task so its outbox clone is released and the writer
        // task can close the socket.
        self._retry.abort();
    }
}

async fn retry_loop(
    pending: Arc<Mutex<HashMap<String, Pending>>>,
    outbox: mpsc::UnboundedSender<Outbound>,
    events: mpsc::UnboundedSender<ClientEvent>,
    base_delay: Duration,
    max_attempts: usize,
) {
    let mut ticker = interval(Duration::from_millis(50));

    loop {
        ticker.tick().await;
        let now = Instant::now();
        let mut resend = Vec::new();
        let mut failed = Vec::new();

        {
            let mut pending = pending.lock().expect("reliability lock");
            for (id, entry) in pending.iter_mut() {
                if entry.next > now {
                    continue;
                }
                if entry.attempts >= max_attempts {
                    failed.push((id.clone(), entry.attempts));
                } else {
                    entry.attempts += 1;
                    entry.next = now + backoff(base_delay, entry.attempts);
                    resend.push(entry.frame.clone());
                }
            }
            for (id, _) in &failed {
                pending.remove(id);
            }
        }

        for frame in resend {
            let _ = outbox.send(Outbound::Frame(frame));
        }
        for (id, attempts) in failed {
            let _ = events.send(ClientEvent::Failed { id, attempts });
        }
    }
}

fn backoff(base: Duration, attempts: usize) -> Duration {
    base * 2u32.pow(attempts.min(31) as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wallet_session_core::{frame::RelayFrameBody, message::Topic};

    fn frame(id: &str) -> RelayFrame {
        RelayFrame {
            v: 1,
            id: id.to_owned(),
            topic: Topic::new([0u8; 32]).expect("topic"),
            body: RelayFrameBody::Message {
                payload: "payload".to_owned(),
            },
        }
    }

    #[test]
    fn ack_classification() {
        assert!(requires_ack(MessageType::Proposal));
        assert!(requires_ack(MessageType::Request));
        assert!(requires_ack(MessageType::Response));
        assert!(!requires_ack(MessageType::Ack));
    }

    #[tokio::test]
    async fn dedupes_seen_ids() {
        let (outbox, _rx) = mpsc::unbounded_channel();
        let (mut reliability, _events) =
            Reliability::spawn(outbox, Duration::from_secs(1), 1, Duration::from_secs(60));

        assert!(!reliability.is_duplicate("x"));
        assert!(reliability.is_duplicate("x"));
        assert!(!reliability.is_duplicate("y"));
    }

    #[tokio::test]
    async fn delivers_when_acked() {
        let (outbox, mut outbound) = mpsc::unbounded_channel();
        let (mut reliability, mut events) =
            Reliability::spawn(outbox, Duration::from_secs(1), 5, Duration::from_secs(60));

        reliability.dispatch(frame("a"), true).expect("dispatch");
        assert!(matches!(outbound.try_recv(), Ok(Outbound::Frame(_))));

        reliability.mark_delivered("a");
        assert_eq!(
            events.try_recv().expect("event"),
            ClientEvent::Delivered { id: "a".to_owned() }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn retries_then_fails() {
        let (outbox, mut outbound) = mpsc::unbounded_channel();
        let (mut reliability, mut events) =
            Reliability::spawn(outbox, Duration::from_secs(1), 2, Duration::from_secs(60));

        reliability.dispatch(frame("a"), true).expect("dispatch");
        assert!(matches!(outbound.try_recv(), Ok(Outbound::Frame(_))));

        // Let the retry task run through the backoff schedule and give up.
        for _ in 0..200 {
            tokio::time::advance(Duration::from_millis(100)).await;
            tokio::task::yield_now().await;
        }

        let mut resends = 0;
        while let Ok(Outbound::Frame(_)) = outbound.try_recv() {
            resends += 1;
        }
        assert!(
            resends >= 2,
            "expected at least two retransmissions, got {resends}"
        );

        let mut failed = None;
        while let Ok(event) = events.try_recv() {
            if let ClientEvent::Failed { id, attempts } = event {
                failed = Some((id, attempts));
            }
        }
        assert_eq!(failed, Some(("a".to_owned(), 2)));
    }
}
