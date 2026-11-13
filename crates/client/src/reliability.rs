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

use crate::{error::ClientError, identity::unix_now, relay::Outbound};

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
    sequence: u64,
    expires_at: u64,
    sent: bool,
}

/// Outbound reliability: ack tracking and retransmission.
pub(crate) struct Reliability {
    outbox: mpsc::Sender<Outbound>,
    pending: Arc<Mutex<HashMap<MessageId, Pending>>>,
    ready: Arc<AtomicBool>,
    events: mpsc::Sender<ClientEvent>,
    base_delay: Duration,
    next_sequence: u64,
    _retry: JoinHandle<()>,
}

impl Reliability {
    pub(crate) fn spawn(
        outbox: mpsc::Sender<Outbound>,
        ready: Arc<AtomicBool>,
        base_delay: Duration,
        max_attempts: usize,
        retransmit_spacing: Duration,
    ) -> (Self, mpsc::Receiver<ClientEvent>) {
        let pending = Arc::new(Mutex::new(HashMap::new()));
        let (events, events_rx) = mpsc::channel(EVENT_CAPACITY);
        let _retry = tokio::spawn(retry_loop(
            Arc::clone(&pending),
            Arc::clone(&ready),
            outbox.clone(),
            events.clone(),
            base_delay,
            max_attempts,
            retransmit_spacing,
        ));

        (
            Self {
                outbox,
                pending,
                ready,
                events,
                base_delay,
                next_sequence: 0,
                _retry,
            },
            events_rx,
        )
    }

    /// Emit an event to the application.
    pub(crate) fn emit(&self, event: ClientEvent) {
        let _ = self.events.try_send(event);
    }

    /// Enqueue a frame, tracking it for retransmission when `track` is set.
    pub(crate) fn dispatch(
        &mut self,
        frame: RelayFrame,
        track: bool,
        ts: u64,
    ) -> Result<(), ClientError> {
        let id = frame.id.clone();
        let is_ready = self.ready.load(Ordering::Relaxed);
        if track {
            let sequence = self.next_sequence;
            self.next_sequence = self.next_sequence.wrapping_add(1);
            let pending = Pending {
                frame: frame.clone(),
                attempts: 0,
                next: Instant::now() + self.base_delay,
                sequence,
                expires_at: ts.saturating_add(300),
                sent: is_ready,
            };
            let mut pending_messages = self.pending.lock().expect("reliability lock");
            if !pending_messages.contains_key(&id) && pending_messages.len() >= PENDING_CAPACITY {
                return Err(ClientError::Busy);
            }
            pending_messages.insert(id.clone(), pending);
        }

        // While the relay session is not ready, tracked frames wait only in
        // the pending map. Sending them now would duplicate the reconnect
        // flush after the transport queue survives a disconnect.
        if track && !is_ready {
            return Ok(());
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

    /// Report and remove every outstanding tracked message.
    pub(crate) fn fail_all(&mut self) {
        let pending: Vec<(MessageId, Pending)> = self
            .pending
            .lock()
            .expect("reliability lock")
            .drain()
            .collect();
        for (id, entry) in pending {
            let _ = self.events.try_send(ClientEvent::Failed {
                id,
                attempts: entry.attempts,
            });
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
    ready: Arc<AtomicBool>,
    outbox: mpsc::Sender<Outbound>,
    events: mpsc::Sender<ClientEvent>,
    base_delay: Duration,
    max_attempts: usize,
    retransmit_spacing: Duration,
) {
    let mut ticker = interval(Duration::from_millis(50));
    let mut was_ready = ready.load(Ordering::Relaxed);
    let mut next_send = Instant::now();

    loop {
        ticker.tick().await;

        let now = Instant::now();
        let now_unix = unix_now();
        let is_ready = ready.load(Ordering::Relaxed);
        let mut resend = None;
        let mut failed = Vec::new();

        {
            let mut pending = pending.lock().expect("reliability lock");

            // An envelope past ts + 300 can no longer be accepted by the peer.
            let expired: Vec<MessageId> = pending
                .iter()
                .filter(|(_, entry)| now_unix > entry.expires_at)
                .map(|(id, _)| id.clone())
                .collect();
            for id in expired {
                if let Some(entry) = pending.remove(&id) {
                    failed.push((id, entry.attempts));
                }
            }

            if is_ready {
                if !was_ready {
                    // A reconnect flush starts now, but is paced below.
                    for entry in pending.values_mut() {
                        entry.next = now;
                    }
                    next_send = now;
                } else {
                    // Frames dispatched while offline still need their first
                    // write, even if the ready edge happened before this tick.
                    for entry in pending.values_mut().filter(|entry| !entry.sent) {
                        entry.next = now;
                    }
                }
            }

            if is_ready && now >= next_send {
                let candidate = pending
                    .iter()
                    .filter(|(_, entry)| entry.next <= now)
                    .map(|(id, entry)| (id.clone(), entry.next, entry.sequence))
                    .min_by_key(|(_, next, sequence)| (*next, *sequence));

                if let Some((id, _, _)) = candidate {
                    let entry = pending.get_mut(&id).expect("candidate exists");
                    if entry.attempts >= max_attempts {
                        if let Some(entry) = pending.remove(&id) {
                            failed.push((id, entry.attempts));
                        }
                    } else {
                        entry.attempts += 1;
                        entry.next = now + backoff(base_delay, entry.attempts);
                        entry.sent = true;
                        resend = Some(entry.frame.clone());
                    }
                }
            }
        }

        was_ready = is_ready;

        if let Some(frame) = resend {
            if outbox.send(Outbound::Frame(frame)).await.is_err() {
                return;
            }
            next_send = now + retransmit_spacing;
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

    fn ready(value: bool) -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(value))
    }

    #[tokio::test]
    async fn reports_a_full_outbound_queue() {
        let (outbox, _outbound) = mpsc::channel(1);
        let (mut reliability, _events) = Reliability::spawn(
            outbox,
            ready(true),
            Duration::from_secs(1),
            5,
            Duration::from_millis(100),
        );

        reliability
            .dispatch(frame("a"), true, unix_now())
            .expect("first dispatch");
        assert!(matches!(
            reliability.dispatch(frame("b"), true, unix_now()),
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
        let (mut reliability, mut events) = Reliability::spawn(
            outbox,
            ready(true),
            Duration::from_secs(1),
            5,
            Duration::from_millis(100),
        );

        reliability
            .dispatch(frame("a"), true, unix_now())
            .expect("dispatch");
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
        let (mut reliability, mut events) = Reliability::spawn(
            outbox,
            ready(true),
            Duration::from_secs(1),
            2,
            Duration::from_millis(100),
        );

        reliability
            .dispatch(frame("a"), true, unix_now())
            .expect("dispatch");
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
        let ready = ready(false);
        let (mut reliability, _events) = Reliability::spawn(
            outbox,
            Arc::clone(&ready),
            Duration::from_secs(1),
            3,
            Duration::from_millis(100),
        );

        reliability
            .dispatch(frame("a"), true, unix_now())
            .expect("dispatch");
        assert!(
            outbound.try_recv().is_err(),
            "a frame dispatched while not ready must not be queued"
        );

        for _ in 0..20 {
            tokio::time::advance(Duration::from_millis(100)).await;
            tokio::task::yield_now().await;
        }
        assert!(
            outbound.try_recv().is_err(),
            "no send expected while disconnected"
        );

        ready.store(true, Ordering::Relaxed);
        for _ in 0..5 {
            tokio::time::advance(Duration::from_millis(100)).await;
            tokio::task::yield_now().await;
        }
        assert!(
            matches!(outbound.try_recv(), Ok(Outbound::Frame(_))),
            "expected a flush after readiness"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn flushes_pending_frames_in_order_and_with_spacing() {
        let (outbox, mut outbound) = mpsc::channel(16);
        let ready = ready(false);
        let (mut reliability, _events) = Reliability::spawn(
            outbox,
            Arc::clone(&ready),
            Duration::from_secs(60),
            5,
            Duration::from_millis(100),
        );

        for id in ["a", "b", "c"] {
            reliability
                .dispatch(frame(id), true, unix_now())
                .expect("dispatch");
        }
        ready.store(true, Ordering::Relaxed);

        let mut sent = Vec::new();
        for _ in 0..20 {
            tokio::time::advance(Duration::from_millis(50)).await;
            tokio::task::yield_now().await;
            while let Ok(Outbound::Frame(frame)) = outbound.try_recv() {
                sent.push(frame.id);
            }
        }
        assert_eq!(sent, [message_id("a"), message_id("b"), message_id("c")]);
    }

    #[tokio::test(start_paused = true)]
    async fn expired_frames_fail_without_sending() {
        let (outbox, mut outbound) = mpsc::channel(16);
        let (mut reliability, mut events) = Reliability::spawn(
            outbox,
            ready(false),
            Duration::from_secs(1),
            5,
            Duration::from_millis(100),
        );

        reliability
            .dispatch(frame("old"), true, unix_now().saturating_sub(301))
            .expect("dispatch");
        for _ in 0..3 {
            tokio::time::advance(Duration::from_millis(100)).await;
            tokio::task::yield_now().await;
        }

        assert!(outbound.try_recv().is_err());
        assert!(matches!(
            events.try_recv(),
            Ok(ClientEvent::Failed { id, .. }) if id == message_id("old")
        ));
    }

    #[tokio::test]
    async fn fail_all_reports_every_pending_frame() {
        let (outbox, _outbound) = mpsc::channel(16);
        let (mut reliability, mut events) = Reliability::spawn(
            outbox,
            ready(false),
            Duration::from_secs(1),
            5,
            Duration::from_millis(100),
        );

        for id in ["a", "b"] {
            reliability
                .dispatch(frame(id), true, unix_now())
                .expect("dispatch");
        }
        reliability.fail_all();

        let mut failed = Vec::new();
        while let Ok(event) = events.try_recv() {
            if let ClientEvent::Failed { id, .. } = event {
                failed.push(id);
            }
        }
        failed.sort_by_key(|id| id.to_string());
        assert_eq!(failed, [message_id("a"), message_id("b")]);
        assert!(reliability.pending.lock().expect("lock").is_empty());
    }
}
