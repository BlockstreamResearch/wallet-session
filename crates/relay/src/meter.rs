//! Wire-level admission for client sockets.
//!
//! The read loop charges complete messages to the inbound budgets, but
//! tungstenite does work on every frame below it: a fragmented message is
//! reassembled from continuation frames that never surface as messages, so a
//! client could stream empty continuations, six bytes each, with nothing ever
//! charged. [`MeteredStream`] sits between the socket and tungstenite and
//! admits bytes against the connection's wire budget before tungstenite sees
//! them: the upgrade request, every frame header and mask, control frames and
//! continuations included, each byte once.
//!
//! A read never takes more than the budget holds. While it is empty the
//! stream leaves the socket alone until the budget has refilled, so the
//! kernel buffers fill and TCP flow control slows the sender down to the
//! budget. Nothing is dropped and the meter never closes a connection: a
//! throttled read returns `Pending`, and the read loop goes on polling its
//! token, pong and idle deadlines meanwhile. Every wait is a timer of at most
//! a second, so a throttled read always resumes.
//!
//! The wire budget is the connection's own, separate from the message-level
//! budgets the read loop charges, per connection and shared. A complete
//! message's payload is therefore not charged twice to one bucket, and bytes
//! that reach no counterpart still spend no shared budget.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::{Instant, Sleep},
};

use crate::limits::{Bucket, RateLimit};

/// Bytes a throttled read waits to have available, or the whole burst if that
/// is smaller, so a throttled stream is read in chunks rather than a few bytes
/// per wakeup.
const WAKE_BYTES: u32 = 4096;

/// Shortest wait before a throttled read tries again.
const MIN_WAIT: Duration = Duration::from_millis(1);

/// Longest wait before a throttled read tries again, however far off the
/// refill it waits for is.
const MAX_WAIT: Duration = Duration::from_secs(1);

/// A socket whose reads are admitted against a wire byte budget.
#[derive(Debug)]
pub struct MeteredStream<S> {
    inner: S,
    budget: Bucket,
    rate: RateLimit,
    /// Wakes a throttled read once the budget has refilled.
    throttle: Option<Pin<Box<Sleep>>>,
}

/// What the wire budget allows a read now.
enum Admission {
    /// Read at most this many bytes.
    Read(u32),

    /// Read nothing before this.
    WaitUntil(Instant),
}

impl<S> MeteredStream<S> {
    /// Admit reads from `inner` at `rate`, starting with a full burst.
    pub(crate) fn new(inner: S, rate: RateLimit) -> Self {
        Self {
            inner,
            budget: Bucket::full(rate.burst, Instant::now()),
            rate,
            throttle: None,
        }
    }

    fn admit(&mut self, now: Instant) -> Admission {
        let available = self.budget.available(self.rate, now);
        if available > 0 {
            return Admission::Read(available);
        }
        let wait = self.budget.time_until(WAKE_BYTES, self.rate);
        Admission::WaitUntil(now + wait.clamp(MIN_WAIT, MAX_WAIT))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for MeteredStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        // Never an empty successful read while throttled: tungstenite would
        // take that for the end of the stream.
        let admitted = loop {
            if let Some(throttle) = this.throttle.as_mut() {
                ready!(throttle.as_mut().poll(cx));
                this.throttle = None;
            }
            match this.admit(Instant::now()) {
                Admission::Read(bytes) => break bytes,
                Admission::WaitUntil(deadline) => {
                    this.throttle = Some(Box::pin(tokio::time::sleep_until(deadline)));
                }
            }
        };

        // No more than was admitted, so tungstenite never parses a byte the
        // budget has not paid for.
        let limit = usize::try_from(admitted)
            .unwrap_or(usize::MAX)
            .min(buf.remaining());
        let read = {
            let mut limited = ReadBuf::new(buf.initialize_unfilled_to(limit));
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut limited))?;
            limited.filled().len()
        };
        buf.advance(read);
        this.budget.spend(u32::try_from(read).unwrap_or(u32::MAX));
        Poll::Ready(Ok(()))
    }
}

/// Writes are the relay's own and pass through unmetered.
impl<S: AsyncWrite + Unpin> AsyncWrite for MeteredStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    use futures_util::StreamExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio_tungstenite::{
        WebSocketStream,
        tungstenite::{Message, protocol::Role},
    };

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const HOUR: Duration = Duration::from_secs(3600);

    /// First bytes of the frames these tests send: FIN bit and opcode.
    const TEXT_FIRST: u8 = 0x01;
    const CONTINUATION: u8 = 0x00;
    const CONTINUATION_FINAL: u8 = 0x80;
    const PING: u8 = 0x89;
    const PONG: u8 = 0x8a;

    /// A client frame as it crosses the wire: masked, with a payload short
    /// enough for the one-byte length.
    fn frame(first: u8, payload: &[u8]) -> Vec<u8> {
        const MASK: [u8; 4] = [0x11, 0x22, 0x33, 0x44];
        let length = u8::try_from(payload.len()).expect("short payload");
        assert!(length < 126, "short payload");
        let mut wire = vec![first, 0x80 | length];
        wire.extend_from_slice(&MASK);
        wire.extend(
            payload
                .iter()
                .zip(MASK.iter().cycle())
                .map(|(byte, mask)| byte ^ mask),
        );
        wire
    }

    /// A text message split into an empty first frame, `continuations` empty
    /// continuation frames, and a final one carrying `text`.
    fn fragmented(continuations: usize, text: &[u8]) -> Vec<u8> {
        let mut wire = frame(TEXT_FIRST, b"");
        for _ in 0..continuations {
            wire.extend(frame(CONTINUATION, b""));
        }
        wire.extend(frame(CONTINUATION_FINAL, text));
        wire
    }

    /// The relay end of a socket, read through a meter at `rate`, and the
    /// client end.
    fn metered(rate: RateLimit) -> (MeteredStream<DuplexStream>, DuplexStream) {
        let (client, relay) = tokio::io::duplex(1 << 20);
        (MeteredStream::new(relay, rate), client)
    }

    /// The relay's WebSocket over a metered socket.
    async fn websocket(
        stream: MeteredStream<DuplexStream>,
    ) -> WebSocketStream<MeteredStream<DuplexStream>> {
        WebSocketStream::from_raw_socket(stream, Role::Server, None).await
    }

    fn left(stream: &mut MeteredStream<DuplexStream>) -> u32 {
        let rate = stream.rate;
        stream.budget.available(rate, Instant::now())
    }

    #[tokio::test(start_paused = true)]
    async fn every_wire_byte_is_charged_once() -> TestResult {
        let rate = RateLimit {
            burst: 1 << 20,
            interval: HOUR,
        };
        let (stream, mut client) = metered(rate);
        let mut websocket = websocket(stream).await;

        // Empty continuations, with control frames between the fragments of
        // the message as the protocol allows.
        let mut wire = frame(TEXT_FIRST, b"");
        for _ in 0..1000 {
            wire.extend(frame(CONTINUATION, b""));
        }
        wire.extend(frame(PING, b"ping"));
        wire.extend(frame(PONG, b""));
        wire.extend(frame(CONTINUATION_FINAL, b"hello"));
        client.write_all(&wire).await?;

        assert!(matches!(websocket.next().await, Some(Ok(Message::Ping(_)))));
        assert!(matches!(websocket.next().await, Some(Ok(Message::Pong(_)))));
        let Some(Ok(Message::Text(text))) = websocket.next().await else {
            return Err("the fragments must make up one text message".into());
        };
        assert_eq!(text.as_str(), "hello");

        // Headers, masks, empty frames and payloads, each byte once.
        let wire = u32::try_from(wire.len())?;
        assert_eq!(left(websocket.get_mut()), rate.burst - wire);
        Ok(())
    }

    /// The bypass the Cloud audit reproduced, scaled down: empty continuation
    /// frames were parsed without bound and charged nothing.
    #[tokio::test(start_paused = true)]
    async fn empty_continuations_are_throttled_to_the_wire_rate() -> TestResult {
        let rate = RateLimit {
            burst: 600,
            interval: Duration::from_secs(1),
        };
        let (stream, mut client) = metered(rate);
        let mut websocket = websocket(stream).await;

        // 6,014 bytes: the 600-byte burst at once, then 600 bytes a second.
        client.write_all(&fragmented(1000, b"hi")).await?;
        let start = Instant::now();
        let Some(Ok(Message::Text(text))) = websocket.next().await else {
            return Err("the fragments must make up one text message".into());
        };
        assert_eq!(text.as_str(), "hi");

        let elapsed = start.elapsed();
        assert!(
            (Duration::from_secs(9)..=Duration::from_secs(11)).contains(&elapsed),
            "the message must take about ten seconds at the wire rate, took {elapsed:?}"
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_read_takes_no_more_than_the_budget_holds() -> TestResult {
        let rate = RateLimit {
            burst: 10,
            interval: Duration::from_secs(1),
        };
        let (mut stream, mut client) = metered(rate);
        client.write_all(&[7; 25]).await?;

        let mut buf = [0u8; 64];
        let start = Instant::now();
        assert_eq!(stream.read(&mut buf).await?, 10, "the burst, at once");
        assert_eq!(start.elapsed(), Duration::ZERO);
        assert_eq!(stream.read(&mut buf).await?, 10, "a refill later");
        assert!(start.elapsed() >= Duration::from_secs(1));
        assert_eq!(stream.read(&mut buf).await?, 5, "what is left");

        // The end of the stream still reads as such.
        drop(client);
        assert_eq!(stream.read(&mut buf).await?, 0);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn writes_pass_through_uncharged() -> TestResult {
        let rate = RateLimit {
            burst: 10,
            interval: HOUR,
        };
        let (mut stream, mut client) = metered(rate);
        stream.write_all(&[1; 100]).await?;

        let mut buf = [0u8; 100];
        client.read_exact(&mut buf).await?;
        assert_eq!(buf, [1; 100]);
        assert_eq!(left(&mut stream), rate.burst);
        Ok(())
    }
}
