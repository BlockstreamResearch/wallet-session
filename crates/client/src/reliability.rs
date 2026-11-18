use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, mpsc},
    task::JoinHandle,
    time::{Instant, interval},
};
use wallet_session_core::{
    frame::RelayFrame,
    message::{MessageId, MessageType},
};

use crate::{config::MAX_RETRY_DELAY, error::ClientError, identity::unix_now, relay::Outbound};

/// Events buffered between the reliability task and the client.
pub(crate) const EVENT_CAPACITY: usize = 256;

/// Maximum pending messages plus unconsumed delivery outcomes per link.
pub(crate) const PENDING_CAPACITY: usize = 256;

/// A delivery event and the reservation it releases when consumed.
pub(crate) type DeliveryEvent = (ClientEvent, OwnedSemaphorePermit);

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
    permit: OwnedSemaphorePermit,
}

/// Outbound reliability: ack tracking and retransmission.
pub(crate) struct Reliability {
    outbox: mpsc::Sender<Outbound>,
    pending: Arc<Mutex<HashMap<MessageId, Pending>>>,
    ready: Arc<AtomicBool>,
    lifecycle: mpsc::Sender<ClientEvent>,
    outcomes: mpsc::UnboundedSender<DeliveryEvent>,
    permits: Arc<Semaphore>,
    base_delay: Duration,
    next_sequence: u64,
    _retry: JoinHandle<()>,
}

impl Reliability {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn spawn(
        outbox: mpsc::Sender<Outbound>,
        ready: Arc<AtomicBool>,
        lifecycle: mpsc::Sender<ClientEvent>,
        outcomes: mpsc::UnboundedSender<DeliveryEvent>,
        base_delay: Duration,
        max_attempts: usize,
        retransmit_spacing: Duration,
        retransmit_bytes_per_second: usize,
    ) -> Self {
        let pending = Arc::new(Mutex::new(HashMap::new()));
        let permits = Arc::new(Semaphore::new(PENDING_CAPACITY));
        let _retry = tokio::spawn(retry_loop(
            Arc::clone(&pending),
            Arc::clone(&ready),
            outbox.clone(),
            outcomes.clone(),
            base_delay,
            max_attempts,
            retransmit_spacing,
            retransmit_bytes_per_second,
        ));

        Self {
            outbox,
            pending,
            ready,
            lifecycle,
            outcomes,
            permits,
            base_delay,
            next_sequence: 0,
            _retry,
        }
    }

    /// Emit a droppable lifecycle event to the application.
    pub(crate) fn emit(&self, event: ClientEvent) {
        let _ = self.lifecycle.try_send(event);
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
            let permit = self
                .permits
                .clone()
                .try_acquire_owned()
                .map_err(|_| ClientError::Busy)?;
            let sequence = self.next_sequence;
            self.next_sequence = self.next_sequence.wrapping_add(1);
            let pending = Pending {
                frame: frame.clone(),
                attempts: 0,
                next: Instant::now() + self.base_delay,
                sequence,
                expires_at: ts.saturating_add(300),
                sent: is_ready,
                permit,
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
            let _ = self.outcomes.send((
                ClientEvent::Failed {
                    id,
                    attempts: entry.attempts,
                },
                entry.permit,
            ));
        }
    }

    /// Record an inbound ACK, reporting delivery. Returns whether it
    /// completed an outstanding send.
    pub(crate) fn mark_delivered(&mut self, ack_id: &MessageId) -> bool {
        let Some(entry) = self
            .pending
            .lock()
            .expect("reliability lock")
            .remove(ack_id)
        else {
            return false;
        };
        let _ = self
            .outcomes
            .send((ClientEvent::Delivered { id: ack_id.clone() }, entry.permit));
        true
    }
}

impl Drop for Reliability {
    fn drop(&mut self) {
        // Stop the retry task so its outbox clone is released and the writer
        // task can close the socket.
        self._retry.abort();
    }
}

#[allow(clippy::too_many_arguments)]
async fn retry_loop(
    pending: Arc<Mutex<HashMap<MessageId, Pending>>>,
    ready: Arc<AtomicBool>,
    outbox: mpsc::Sender<Outbound>,
    outcomes: mpsc::UnboundedSender<DeliveryEvent>,
    base_delay: Duration,
    max_attempts: usize,
    retransmit_spacing: Duration,
    retransmit_bytes_per_second: usize,
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
                    failed.push((id, entry));
                }
            }

            if is_ready {
                if !was_ready {
                    // A reconnect flush starts now, but is paced below.
                    next_send = now;
                }
                // Only frames that were never written on this connection
                // need their first write. A frame dispatched after the relay
                // became ready was already sent by `dispatch`; resetting its
                // deadline here would duplicate it. Keep entries already in
                // their final ack wait on their original deadline instead of
                // failing them immediately.
                for entry in pending
                    .values_mut()
                    .filter(|entry| !entry.sent && entry.attempts < max_attempts)
                {
                    entry.next = now;
                }
            } else {
                // A frame written on a connection that ended is not known to
                // have reached the peer. Retry it after the next ready edge,
                // but leave final-ack waits on their original deadline.
                for entry in pending
                    .values_mut()
                    .filter(|entry| entry.attempts < max_attempts)
                {
                    entry.sent = false;
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
                            failed.push((id, entry));
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
            let frame_len = serde_json::to_string(&frame)
                .map(|text| text.len())
                .unwrap_or(0);
            if outbox.send(Outbound::Frame(frame)).await.is_err() {
                return;
            }
            let byte_delay =
                Duration::from_secs_f64(frame_len as f64 / retransmit_bytes_per_second as f64);
            let spacing = retransmit_spacing.max(byte_delay);
            next_send = now.checked_add(spacing).unwrap_or(now + MAX_RETRY_DELAY);
        }

        for (id, entry) in failed {
            let _ = outcomes.send((
                ClientEvent::Failed {
                    id,
                    attempts: entry.attempts,
                },
                entry.permit,
            ));
        }
    }
}

fn backoff(base: Duration, attempts: usize) -> Duration {
    base.saturating_mul(2u32.pow(attempts.min(31) as u32))
        .min(MAX_RETRY_DELAY)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wallet_session_core::{frame::RelayFrameBody, message::Topic};

    struct TestEvents {
        lifecycle: mpsc::Receiver<ClientEvent>,
        outcomes: mpsc::UnboundedReceiver<DeliveryEvent>,
    }

    impl TestEvents {
        fn try_recv(&mut self) -> Option<ClientEvent> {
            self.outcomes
                .try_recv()
                .ok()
                .map(|(event, _permit)| event)
                .or_else(|| self.lifecycle.try_recv().ok())
        }
    }

    fn spawn_reliability(
        outbox: mpsc::Sender<Outbound>,
        ready: Arc<AtomicBool>,
        base_delay: Duration,
        max_attempts: usize,
        retransmit_spacing: Duration,
    ) -> (Reliability, TestEvents) {
        spawn_reliability_with_bytes(
            outbox,
            ready,
            base_delay,
            max_attempts,
            retransmit_spacing,
            256 * 1024,
        )
    }

    fn spawn_reliability_with_bytes(
        outbox: mpsc::Sender<Outbound>,
        ready: Arc<AtomicBool>,
        base_delay: Duration,
        max_attempts: usize,
        retransmit_spacing: Duration,
        retransmit_bytes_per_second: usize,
    ) -> (Reliability, TestEvents) {
        let (lifecycle, lifecycle_rx) = mpsc::channel(EVENT_CAPACITY);
        let (outcomes, outcomes_rx) = mpsc::unbounded_channel();
        let reliability = Reliability::spawn(
            outbox,
            ready,
            lifecycle,
            outcomes,
            base_delay,
            max_attempts,
            retransmit_spacing,
            retransmit_bytes_per_second,
        );
        (
            reliability,
            TestEvents {
                lifecycle: lifecycle_rx,
                outcomes: outcomes_rx,
            },
        )
    }

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

    #[tokio::test]
    async fn delivery_outcomes_survive_a_full_lifecycle_queue() {
        let (outbox, _outbound) = mpsc::channel(16);
        let (lifecycle, mut lifecycle_rx) = mpsc::channel(1);
        let (outcomes, mut outcomes_rx) = mpsc::unbounded_channel();
        let mut reliability = Reliability::spawn(
            outbox,
            ready(true),
            lifecycle,
            outcomes,
            Duration::from_secs(1),
            5,
            Duration::from_millis(100),
            256 * 1024,
        );

        // Fill and overflow the droppable lifecycle channel.
        reliability.emit(ClientEvent::Reconnecting);
        reliability.emit(ClientEvent::Reconnected);

        reliability
            .dispatch(frame("a"), true, unix_now())
            .expect("dispatch");
        reliability.mark_delivered(&message_id("a"));

        let (event, _permit) = outcomes_rx.try_recv().expect("delivery outcome");
        assert_eq!(
            event,
            ClientEvent::Delivered {
                id: message_id("a")
            }
        );
        assert!(lifecycle_rx.try_recv().is_ok());
    }

    #[tokio::test]
    async fn delivered_outcomes_hold_capacity_until_consumed() {
        let (outbox, _outbound) = mpsc::channel(16);
        let ready = ready(false);
        let (mut reliability, mut events) = spawn_reliability(
            outbox,
            Arc::clone(&ready),
            Duration::from_secs(60),
            5,
            Duration::from_millis(100),
        );

        for index in 0..PENDING_CAPACITY {
            let label = format!("d{index}");
            reliability
                .dispatch(frame(&label), true, unix_now())
                .expect("dispatch");
            reliability.mark_delivered(&message_id(&label));
        }

        // Every outcome still holds its permit.
        assert!(matches!(
            reliability.dispatch(frame("overflow"), true, unix_now()),
            Err(ClientError::Busy)
        ));

        // Consuming one outcome releases one reservation.
        let _ = events.outcomes.try_recv().expect("delivery outcome");
        reliability
            .dispatch(frame("replacement"), true, unix_now())
            .expect("released capacity");
    }

    #[tokio::test]
    async fn failed_outcomes_hold_capacity_until_consumed() {
        let (outbox, _outbound) = mpsc::channel(16);
        let ready = ready(false);
        let (mut reliability, mut events) = spawn_reliability(
            outbox,
            Arc::clone(&ready),
            Duration::from_secs(60),
            5,
            Duration::from_millis(100),
        );

        for index in 0..PENDING_CAPACITY {
            reliability
                .dispatch(frame(&format!("f{index}")), true, unix_now())
                .expect("dispatch");
        }
        reliability.fail_all();

        assert!(matches!(
            reliability.dispatch(frame("overflow"), true, unix_now()),
            Err(ClientError::Busy)
        ));

        let _ = events.outcomes.try_recv().expect("failed outcome");
        reliability
            .dispatch(frame("replacement"), true, unix_now())
            .expect("released capacity");
    }

    #[test]
    fn ack_classification() {
        assert!(requires_ack(MessageType::Proposal));
        assert!(requires_ack(MessageType::Request));
        assert!(requires_ack(MessageType::Response));
        assert!(!requires_ack(MessageType::Ack));
    }

    #[test]
    fn backoff_is_capped_at_the_retry_window() {
        assert_eq!(backoff(Duration::from_secs(1), 1), Duration::from_secs(2));
        assert_eq!(backoff(Duration::from_secs(1), 31), MAX_RETRY_DELAY);
    }

    #[tokio::test(start_paused = true)]
    async fn huge_retransmit_spacing_does_not_overflow() {
        let (outbox, mut outbound) = mpsc::channel(16);
        let ready = ready(false);
        let (mut reliability, _events) = spawn_reliability(
            outbox,
            Arc::clone(&ready),
            Duration::from_secs(1),
            5,
            Duration::MAX,
        );

        reliability
            .dispatch(frame("a"), true, unix_now())
            .expect("dispatch");
        ready.store(true, Ordering::Relaxed);
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;

        assert!(matches!(outbound.try_recv(), Ok(Outbound::Frame(_))));
    }

    fn ready(value: bool) -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(value))
    }

    #[tokio::test]
    async fn reports_a_full_outbound_queue() {
        let (outbox, _outbound) = mpsc::channel(1);
        let (mut reliability, _events) = spawn_reliability(
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
        let (mut reliability, mut events) = spawn_reliability(
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
        let (mut reliability, mut events) = spawn_reliability(
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
        assert_eq!(resends, 2, "expected exactly two retransmissions");

        let mut failed = None;
        while let Some(event) = events.try_recv() {
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
        let (mut reliability, _events) = spawn_reliability(
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
    async fn ready_edge_does_not_duplicate_a_frame_sent_after_readiness() {
        let (outbox, mut outbound) = mpsc::channel(16);
        let ready = ready(false);
        let (mut reliability, _events) = spawn_reliability(
            outbox,
            Arc::clone(&ready),
            Duration::from_secs(60),
            5,
            Duration::from_millis(100),
        );

        // Let the retry task observe the disconnected state.
        for _ in 0..5 {
            tokio::time::advance(Duration::from_millis(50)).await;
            tokio::task::yield_now().await;
        }

        // The link becomes ready and dispatch writes the frame before the
        // retry task's next tick observes the ready edge.
        ready.store(true, Ordering::Relaxed);
        reliability
            .dispatch(frame("a"), true, unix_now())
            .expect("dispatch");
        assert!(matches!(outbound.try_recv(), Ok(Outbound::Frame(_))));
        while outbound.try_recv().is_ok() {}

        // Treating that edge as a reconnect flush would duplicate the frame.
        for _ in 0..5 {
            tokio::time::advance(Duration::from_millis(50)).await;
            tokio::task::yield_now().await;
        }
        assert!(
            outbound.try_recv().is_err(),
            "the ready edge must not duplicate a frame sent after readiness"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn reconnect_flushes_a_frame_sent_before_disconnect() {
        let (outbox, mut outbound) = mpsc::channel(16);
        let ready = ready(true);
        let (mut reliability, _events) = spawn_reliability(
            outbox,
            Arc::clone(&ready),
            Duration::from_secs(60),
            5,
            Duration::from_millis(100),
        );

        reliability
            .dispatch(frame("a"), true, unix_now())
            .expect("dispatch");
        assert!(matches!(outbound.try_recv(), Ok(Outbound::Frame(_))));

        // Observe the disconnect, then the reconnect.
        ready.store(false, Ordering::Relaxed);
        for _ in 0..5 {
            tokio::time::advance(Duration::from_millis(50)).await;
            tokio::task::yield_now().await;
        }
        ready.store(true, Ordering::Relaxed);
        for _ in 0..5 {
            tokio::time::advance(Duration::from_millis(50)).await;
            tokio::task::yield_now().await;
        }

        assert!(
            matches!(outbound.try_recv(), Ok(Outbound::Frame(_))),
            "reconnect must flush a frame sent before the disconnect"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn flushes_pending_frames_in_order_and_with_spacing() {
        let (outbox, mut outbound) = mpsc::channel(16);
        let ready = ready(false);
        let (mut reliability, _events) = spawn_reliability(
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

        let start = Instant::now();
        let mut sent: Vec<(Duration, MessageId)> = Vec::new();
        for _ in 0..20 {
            tokio::time::advance(Duration::from_millis(50)).await;
            tokio::task::yield_now().await;
            while let Ok(Outbound::Frame(frame)) = outbound.try_recv() {
                sent.push((Instant::now().duration_since(start), frame.id));
            }
        }

        let ids: Vec<MessageId> = sent.iter().map(|(_, id)| id.clone()).collect();
        assert_eq!(ids, [message_id("a"), message_id("b"), message_id("c")]);
        assert_eq!(sent.len(), 3);
        assert!(
            sent[1].0 >= sent[0].0 + Duration::from_millis(100),
            "second frame was not spaced: {:?}",
            sent
        );
        assert!(
            sent[2].0 >= sent[1].0 + Duration::from_millis(100),
            "third frame was not spaced: {:?}",
            sent
        );
    }

    #[tokio::test(start_paused = true)]
    async fn full_pending_queue_flushes_every_frame_in_order() {
        let (outbox, mut outbound) = mpsc::channel(16);
        let ready = ready(false);
        let (mut reliability, _events) = spawn_reliability(
            outbox,
            Arc::clone(&ready),
            Duration::from_secs(60),
            5,
            Duration::from_millis(1),
        );

        let mut expected = Vec::new();
        for index in 0..PENDING_CAPACITY {
            let id = format!("f{index}");
            reliability
                .dispatch(frame(&id), true, unix_now())
                .expect("dispatch");
            expected.push(message_id(&id));
        }
        assert!(matches!(
            reliability.dispatch(frame("overflow"), true, unix_now()),
            Err(ClientError::Busy)
        ));

        ready.store(true, Ordering::Relaxed);
        let mut sent = Vec::new();
        for _ in 0..(PENDING_CAPACITY * 2) {
            tokio::time::advance(Duration::from_millis(50)).await;
            tokio::task::yield_now().await;
            while let Ok(Outbound::Frame(frame)) = outbound.try_recv() {
                sent.push(frame.id);
            }
            if sent.len() == PENDING_CAPACITY {
                break;
            }
        }

        assert_eq!(sent, expected);
    }

    #[tokio::test(start_paused = true)]
    async fn reconnect_flush_does_not_fail_a_final_ack_wait_early() {
        let (outbox, mut outbound) = mpsc::channel(16);
        let ready = ready(true);
        let (mut reliability, mut events) = spawn_reliability(
            outbox,
            Arc::clone(&ready),
            Duration::from_secs(1),
            1,
            Duration::from_millis(10),
        );

        reliability
            .dispatch(frame("a"), true, unix_now())
            .expect("dispatch");
        while outbound.try_recv().is_ok() {}

        // Consume the single retry; the entry now waits for its final ack.
        tokio::time::advance(Duration::from_millis(1_100)).await;
        tokio::task::yield_now().await;
        while outbound.try_recv().is_ok() {}

        // A frame sent before the disconnect is only flushed again when the
        // retry task observes a real ready edge. Use it to synchronise on the
        // retry task having seen `ready == false`.
        reliability
            .dispatch(frame("probe"), true, unix_now())
            .expect("dispatch");
        assert!(matches!(outbound.try_recv(), Ok(Outbound::Frame(_))));

        ready.store(false, Ordering::Relaxed);
        tokio::time::advance(Duration::from_millis(100)).await;
        tokio::task::yield_now().await;

        ready.store(true, Ordering::Relaxed);
        tokio::time::advance(Duration::from_millis(200)).await;
        tokio::task::yield_now().await;
        assert!(
            matches!(
                outbound.try_recv(),
                Ok(Outbound::Frame(frame)) if frame.id == message_id("probe")
            ),
            "the retry task must have observed the disconnected state"
        );

        // The final ack wait for `a` must not be failed at the ready edge.
        assert!(
            events.try_recv().is_none(),
            "the final ack wait must be allowed to finish"
        );

        tokio::time::advance(Duration::from_secs(3)).await;
        tokio::task::yield_now().await;
        let mut failed_a = false;
        while let Some(event) = events.try_recv() {
            if let ClientEvent::Failed { id, attempts } = event
                && id == message_id("a")
            {
                assert_eq!(attempts, 1);
                failed_a = true;
            }
        }
        assert!(failed_a, "the final ack wait must eventually fail");
    }

    #[tokio::test(start_paused = true)]
    async fn reconnect_flush_paces_by_bytes() {
        let (outbox, mut outbound) = mpsc::channel(16);
        let ready = ready(false);
        let (mut reliability, _events) = spawn_reliability_with_bytes(
            outbox,
            Arc::clone(&ready),
            Duration::from_secs(60),
            5,
            Duration::from_millis(1),
            100,
        );

        for id in ["a", "b"] {
            let mut frame = frame(id);
            if let RelayFrameBody::Message { payload } = &mut frame.body {
                *payload = "x".repeat(500);
            }
            reliability
                .dispatch(frame, true, unix_now())
                .expect("dispatch");
        }
        ready.store(true, Ordering::Relaxed);

        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert!(
            matches!(outbound.try_recv(), Ok(Outbound::Frame(_))),
            "the first frame should be sent"
        );
        assert!(
            outbound.try_recv().is_err(),
            "the second frame must wait for the byte budget"
        );

        tokio::time::advance(Duration::from_secs(10)).await;
        tokio::task::yield_now().await;
        assert!(
            matches!(outbound.try_recv(), Ok(Outbound::Frame(_))),
            "the second frame should follow after the byte delay"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn expired_frames_fail_without_sending() {
        let (outbox, mut outbound) = mpsc::channel(16);
        let (mut reliability, mut events) = spawn_reliability(
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
            Some(ClientEvent::Failed { id, .. }) if id == message_id("old")
        ));
    }

    #[tokio::test]
    async fn fail_all_reports_every_pending_frame() {
        let (outbox, _outbound) = mpsc::channel(16);
        let (mut reliability, mut events) = spawn_reliability(
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
        while let Some(event) = events.try_recv() {
            if let ClientEvent::Failed { id, .. } = event {
                failed.push(id);
            }
        }
        failed.sort_by_key(|id| id.to_string());
        assert_eq!(failed, [message_id("a"), message_id("b")]);
        assert!(reliability.pending.lock().expect("lock").is_empty());
    }
}
