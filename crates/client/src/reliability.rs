use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tokio::{
    sync::mpsc,
    task::JoinHandle,
    time::{Instant, interval},
};
use wallet_session_core::{
    frame::RelayFrame,
    message::{MessageId, MessageType},
};

use crate::{error::ClientError, relay::Outbound};

/// Events buffered between the reliability task and the client.
const EVENT_CAPACITY: usize = 256;

/// Maximum messages kept for retransmission per link.
const PENDING_CAPACITY: usize = 256;

/// Reliability events surfaced to the application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientEvent {
    /// A sent message was acknowledged by the peer.
    Delivered {
        /// Envelope id that was acknowledged.
        id: MessageId,
    },

    /// A sent message exhausted its retransmissions.
    Failed {
        /// Envelope id that never got acknowledged.
        id: MessageId,

        /// Retransmissions attempted.
        attempts: usize,
    },

    /// The relay connection was lost and a reconnect is starting.
    Reconnecting,

    /// The relay connection was re-established.
    Reconnected,
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

/// Outbound reliability: ack tracking and retransmission.
pub(crate) struct Reliability {
    outbox: mpsc::Sender<Outbound>,
    pending: Arc<Mutex<HashMap<MessageId, Pending>>>,
    connected: Arc<AtomicBool>,
    events: mpsc::Sender<ClientEvent>,
    base_delay: Duration,
    _retry: JoinHandle<()>,
}

impl Reliability {
    pub(crate) fn spawn(
        outbox: mpsc::Sender<Outbound>,
        base_delay: Duration,
        max_attempts: usize,
    ) -> (Self, mpsc::Receiver<ClientEvent>) {
        let pending = Arc::new(Mutex::new(HashMap::new()));
        let connected = Arc::new(AtomicBool::new(false));
        let (events, events_rx) = mpsc::channel(EVENT_CAPACITY);
        let _retry = tokio::spawn(retry_loop(
            Arc::clone(&pending),
            Arc::clone(&connected),
            outbox.clone(),
            events.clone(),
            base_delay,
            max_attempts,
        ));

        (
            Self {
                outbox,
                pending,
                connected,
                events,
                base_delay,
                _retry,
            },
            events_rx,
        )
    }

    /// Report the transport connection state; on reconnect, flush pending.
    pub(crate) fn set_connected(&mut self, connected: bool) {
        self.connected.store(connected, Ordering::Relaxed);
        if connected {
            let now = Instant::now();
            let mut pending = self.pending.lock().expect("reliability lock");
            for entry in pending.values_mut() {
                entry.next = now;
            }
        }
    }

    /// Emit an event to the application.
    pub(crate) fn emit(&self, event: ClientEvent) {
        let _ = self.events.try_send(event);
    }

    /// Enqueue a frame, tracking it for retransmission when `track` is set.
    pub(crate) fn dispatch(&mut self, frame: RelayFrame, track: bool) -> Result<(), ClientError> {
        let id = frame.id.clone();
        if track {
            let pending = Pending {
                frame: frame.clone(),
                attempts: 0,
                next: Instant::now() + self.base_delay,
            };
            let mut pending_messages = self.pending.lock().expect("reliability lock");
            if !pending_messages.contains_key(&id) && pending_messages.len() >= PENDING_CAPACITY {
                return Err(ClientError::Busy);
            }
            pending_messages.insert(id.clone(), pending);
        }

        match self.outbox.try_send(Outbound::Frame(frame)) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                if track {
                    self.pending.lock().expect("reliability lock").remove(&id);
                }
                Err(ClientError::Busy)
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                if track {
                    self.pending.lock().expect("reliability lock").remove(&id);
                }
                Err(ClientError::Closed)
            }
        }
    }

    /// Record an inbound ACK, reporting delivery.
    pub(crate) fn mark_delivered(&mut self, ack_id: &MessageId) {
        if self
            .pending
            .lock()
            .expect("reliability lock")
            .remove(ack_id)
            .is_some()
        {
            let _ = self
                .events
                .try_send(ClientEvent::Delivered { id: ack_id.clone() });
        }
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
    pending: Arc<Mutex<HashMap<MessageId, Pending>>>,
    connected: Arc<AtomicBool>,
    outbox: mpsc::Sender<Outbound>,
    events: mpsc::Sender<ClientEvent>,
    base_delay: Duration,
    max_attempts: usize,
) {
    let mut ticker = interval(Duration::from_millis(50));

    loop {
        ticker.tick().await;

        // Pause retransmission while the transport is down; flushed on reconnect.
        if !connected.load(Ordering::Relaxed) {
            continue;
        }

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
            if outbox.send(Outbound::Frame(frame)).await.is_err() {
                return;
            }
        }
        for (id, attempts) in failed {
            let _ = events.try_send(ClientEvent::Failed { id, attempts });
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

    /// A distinct, valid message id for a test label.
    fn message_id(label: &str) -> MessageId {
        let mut bytes = [0u8; MessageId::LEN];
        let label = &label.as_bytes()[..label.len().min(MessageId::LEN)];
        bytes[..label.len()].copy_from_slice(label);
        MessageId::from_bytes(bytes)
    }

    fn frame(id: &str) -> RelayFrame {
        RelayFrame {
            v: 1,
            id: message_id(id),
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
    async fn reports_a_full_outbound_queue() {
        let (outbox, _outbound) = mpsc::channel(1);
        let (mut reliability, _events) = Reliability::spawn(outbox, Duration::from_secs(1), 5);

        reliability
            .dispatch(frame("a"), true)
            .expect("first dispatch");
        assert!(matches!(
            reliability.dispatch(frame("b"), true),
            Err(ClientError::Busy)
        ));
        assert_eq!(
            reliability.pending.lock().expect("reliability lock").len(),
            1,
            "a refused frame must not stay pending"
        );
    }

    #[tokio::test]
    async fn delivers_when_acked() {
        let (outbox, mut outbound) = mpsc::channel(16);
        let (mut reliability, mut events) = Reliability::spawn(outbox, Duration::from_secs(1), 5);

        reliability.dispatch(frame("a"), true).expect("dispatch");
        assert!(matches!(outbound.try_recv(), Ok(Outbound::Frame(_))));

        reliability.mark_delivered(&message_id("a"));
        assert_eq!(
            events.try_recv().expect("event"),
            ClientEvent::Delivered {
                id: message_id("a")
            }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn retries_then_fails() {
        let (outbox, mut outbound) = mpsc::channel(16);
        let (mut reliability, mut events) = Reliability::spawn(outbox, Duration::from_secs(1), 2);

        reliability.dispatch(frame("a"), true).expect("dispatch");
        reliability.set_connected(true);
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
        assert_eq!(failed, Some((message_id("a"), 2)));
    }

    #[tokio::test(start_paused = true)]
    async fn pauses_while_disconnected_and_flushes_on_reconnect() {
        let (outbox, mut outbound) = mpsc::channel(16);
        let (mut reliability, _events) = Reliability::spawn(outbox, Duration::from_secs(1), 3);

        // Reliability starts disconnected.
        reliability.dispatch(frame("a"), true).expect("dispatch");
        assert!(matches!(outbound.try_recv(), Ok(Outbound::Frame(_))));

        // No retransmission while the transport is down.
        for _ in 0..20 {
            tokio::time::advance(Duration::from_millis(100)).await;
            tokio::task::yield_now().await;
        }
        assert!(
            outbound.try_recv().is_err(),
            "no resend expected while disconnected"
        );

        // Reconnect flushes pending immediately.
        reliability.set_connected(true);
        for _ in 0..5 {
            tokio::time::advance(Duration::from_millis(100)).await;
            tokio::task::yield_now().await;
        }
        assert!(
            matches!(outbound.try_recv(), Ok(Outbound::Frame(_))),
            "expected a flush resend after reconnect"
        );
    }
}
