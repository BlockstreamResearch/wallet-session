use std::collections::VecDeque;
use std::fmt::{self, Write as _};
use std::io::{self, Write};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, mpsc};
use std::thread;
use std::time::Duration;

use tracing::Subscriber;
use tracing::subscriber::set_global_default;
use tracing_bunyan_formatter::{BunyanFormattingLayer, JsonStorageLayer};
use tracing_log::LogTracer;
use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{EnvFilter, Registry};

/// Service name written into every log record.
pub const SERVICE_NAME: &str = "wallet-session-relay";

/// Bytes of log records [`non_blocking`] holds while its sink catches up.
pub const LOG_BUFFER_BYTES: usize = 8 * 1024 * 1024;

/// How long dropping a [`LogGuard`] waits for held records to be written.
const LOG_FLUSH_TIMEOUT: Duration = Duration::from_secs(1);

/// Longest rendering, in bytes, of a client-influenced value in a log record.
pub(crate) const MAX_LOGGED_DISPLAY_BYTES: usize = 256;

/// Build the subscriber: one bunyan JSON record per event, written to `sink`.
///
/// `RUST_LOG` overrides `env_filter`. Either way `tungstenite` logs at debug
/// at most: at trace it writes out every frame it reads or writes, and with
/// them the topics they carry.
pub fn get_subscriber<Sink>(
    name: String,
    env_filter: String,
    sink: Sink,
) -> impl Subscriber + Send + Sync
where
    Sink: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(env_filter));
    subscriber(name, env_filter, sink)
}

/// [`get_subscriber`] with an explicit filter.
fn subscriber<Sink>(
    name: String,
    env_filter: EnvFilter,
    sink: Sink,
) -> impl Subscriber + Send + Sync
where
    Sink: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    let no_frame_dumps = filter_fn(|metadata| {
        let target = metadata.target();
        let tungstenite = target == "tungstenite" || target.starts_with("tungstenite::");
        !(tungstenite && *metadata.level() == tracing::Level::TRACE)
    });
    let formatting_layer = BunyanFormattingLayer::new(name, sink);
    Registry::default()
        .with(env_filter)
        .with(no_frame_dumps)
        .with(JsonStorageLayer)
        .with(formatting_layer)
}

/// Install `subscriber` and route `log` records into it.
pub fn init_subscriber(subscriber: impl Subscriber + Send + Sync) {
    LogTracer::init().expect("Failed to set logger");
    set_global_default(subscriber).expect("Failed to set subscriber");
}

/// Render `value` for a log record, cut to [`MAX_LOGGED_DISPLAY_BYTES`] and
/// with control characters replaced, so a value that echoes client input
/// cannot make the record long.
pub(crate) fn bounded<T: fmt::Display>(value: T) -> Bounded<T> {
    Bounded(value)
}

/// See [`bounded`].
pub(crate) struct Bounded<T>(T);

impl<T: fmt::Display> fmt::Display for Bounded<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = Truncating {
            out: f,
            left: MAX_LOGGED_DISPLAY_BYTES,
            cut: false,
        };
        let written = write!(out, "{}", self.0);
        match written {
            _ if out.cut => out.out.write_str("..."),
            result => result,
        }
    }
}

/// Passes characters through until `left` bytes are used up, then fails,
/// which also stops formatting the rest of the value. Nothing is passed
/// through after a cut, even to a value that writes on regardless.
struct Truncating<'a, 'b> {
    out: &'a mut fmt::Formatter<'b>,
    left: usize,
    cut: bool,
}

impl fmt::Write for Truncating<'_, '_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for c in s.chars() {
            // The JSON encoding would write each of these six bytes long.
            let c = if c.is_control() {
                char::REPLACEMENT_CHARACTER
            } else {
                c
            };
            let Some(left) = self.left.checked_sub(c.len_utf8()) else {
                self.cut = true;
                self.left = 0;
                return Err(fmt::Error);
            };
            self.left = left;
            self.out.write_char(c)?;
        }
        Ok(())
    }
}

/// Start a log writer that hands records to a thread writing them to
/// `sink`, so the threads that log never wait for the sink.
///
/// Up to [`LOG_BUFFER_BYTES`] of records wait for the sink. A record that
/// does not fit is dropped, and the number dropped is logged once the sink
/// has caught up. Dropping the guard writes out what is held, waiting up to
/// a second.
pub fn non_blocking<W>(sink: W) -> io::Result<(NonBlocking, LogGuard)>
where
    W: Write + Send + 'static,
{
    NonBlocking::spawn(sink, LOG_BUFFER_BYTES)
}

/// Log writer returned by [`non_blocking`].
#[derive(Clone)]
pub struct NonBlocking {
    shared: Arc<Shared>,
}

/// Stops the [`non_blocking`] writer once it has written out what it holds.
#[must_use = "dropping the guard stops the log writer"]
pub struct LogGuard {
    shared: Arc<Shared>,
    stopped: mpsc::Receiver<()>,
}

/// One log record on its way to the writer, queued whole when dropped.
pub struct Record<'a> {
    shared: &'a Shared,
    bytes: Vec<u8>,
    oversized: bool,
}

struct Shared {
    queue: Mutex<Queue>,
    ready: Condvar,
    capacity: usize,
}

#[derive(Default)]
struct Queue {
    /// Records waiting for the sink, oldest first.
    records: VecDeque<Vec<u8>>,

    /// Bytes of the waiting records and of the one being written.
    bytes: usize,

    /// Records dropped since the writer last reported them.
    dropped: u64,

    /// Set by the guard: write out what is held, then stop.
    closing: bool,
}

/// What the writer thread does next.
enum Next {
    Write(Vec<u8>),
    ReportDropped(u64),
}

impl NonBlocking {
    fn spawn<W>(sink: W, capacity: usize) -> io::Result<(Self, LogGuard)>
    where
        W: Write + Send + 'static,
    {
        let shared = Arc::new(Shared {
            queue: Mutex::default(),
            ready: Condvar::new(),
            capacity,
        });
        let (stopped_tx, stopped) = mpsc::channel();
        thread::Builder::new()
            .name("log-writer".to_owned())
            .spawn({
                let shared = Arc::clone(&shared);
                move || {
                    write_records(&shared, sink);
                    let _ = stopped_tx.send(());
                }
            })?;
        let writer = Self {
            shared: Arc::clone(&shared),
        };
        Ok((writer, LogGuard { shared, stopped }))
    }
}

impl<'a> MakeWriter<'a> for NonBlocking {
    type Writer = Record<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        Record {
            shared: &self.shared,
            bytes: Vec::new(),
            oversized: false,
        }
    }
}

impl Write for Record<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // A record that can never fit is dropped without copying the rest.
        if self.bytes.len().saturating_add(buf.len()) > self.shared.capacity {
            self.oversized = true;
            self.bytes = Vec::new();
        }
        if !self.oversized {
            self.bytes.extend_from_slice(buf);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for Record<'_> {
    fn drop(&mut self) {
        if self.oversized {
            self.shared.drop_record();
        } else if !self.bytes.is_empty() {
            self.shared.push(std::mem::take(&mut self.bytes));
        }
    }
}

impl Drop for LogGuard {
    fn drop(&mut self) {
        self.shared.lock().closing = true;
        self.shared.ready.notify_one();
        let _ = self.stopped.recv_timeout(LOG_FLUSH_TIMEOUT);
    }
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Queue> {
        // Nothing that can panic runs under the lock.
        self.queue.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Queue `record` if the buffer has room for it, or drop it.
    fn push(&self, record: Vec<u8>) {
        let mut queue = self.lock();
        if record.len() <= self.capacity.saturating_sub(queue.bytes) {
            queue.bytes += record.len();
            queue.records.push_back(record);
        } else {
            queue.dropped += 1;
        }
        drop(queue);
        self.ready.notify_one();
    }

    fn drop_record(&self) {
        self.lock().dropped += 1;
        self.ready.notify_one();
    }
}

/// Write records to `sink` as they arrive, until the guard is dropped and
/// nothing is held any more. The lock is never held while writing.
fn write_records<W: Write>(shared: &Shared, mut sink: W) {
    loop {
        let next = {
            let mut queue = shared.lock();
            loop {
                if let Some(record) = queue.records.pop_front() {
                    break Next::Write(record);
                }
                if queue.dropped > 0 {
                    break Next::ReportDropped(std::mem::take(&mut queue.dropped));
                }
                if queue.closing {
                    return;
                }
                queue = shared
                    .ready
                    .wait(queue)
                    .unwrap_or_else(PoisonError::into_inner);
            }
        };
        match next {
            Next::Write(record) => {
                // A failed write loses this record only.
                let _ = sink.write_all(&record).and_then(|()| sink.flush());
                shared.lock().bytes -= record.len();
            }
            // The queue is empty, so the report has room.
            Next::ReportDropped(dropped) => {
                tracing::warn!(dropped, "log output fell behind; dropped log records");
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use super::*;
    use tracing::subscriber::DefaultGuard;

    /// Log output written to memory.
    #[derive(Clone, Default)]
    pub(crate) struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

    impl CapturedLogs {
        /// The lines written so far: one JSON record each.
        pub(crate) fn records(&self) -> Vec<String> {
            let bytes = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            String::from_utf8_lossy(&bytes)
                .lines()
                .map(str::to_owned)
                .collect()
        }
    }

    impl Write for CapturedLogs {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for CapturedLogs {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Capture the records logged on this thread through the relay's own
    /// subscriber, with `filter` in place of `RUST_LOG`, until the guard is
    /// dropped.
    pub(crate) fn capture(filter: &str) -> (CapturedLogs, DefaultGuard) {
        // `log` records reach the subscriber through the global logger.
        let _ = LogTracer::init();
        let logs = CapturedLogs::default();
        let subscriber = subscriber(
            SERVICE_NAME.to_owned(),
            EnvFilter::new(filter),
            logs.clone(),
        );
        (logs, tracing::subscriber::set_default(subscriber))
    }
}

#[cfg(test)]
mod tests {
    use super::test_utils::CapturedLogs;
    use super::*;

    #[test]
    fn bounded_cuts_long_values_and_replaces_control_characters() {
        assert_eq!(bounded("short value").to_string(), "short value");
        assert_eq!(bounded("a\u{7f}b\nc").to_string(), "a\u{fffd}b\u{fffd}c");

        let long = bounded("x".repeat(100_000)).to_string();
        assert_eq!(long.len(), MAX_LOGGED_DISPLAY_BYTES + "...".len());
        assert!(long.ends_with("..."));

        // Characters are never split.
        let wide = bounded("€".repeat(MAX_LOGGED_DISPLAY_BYTES)).to_string();
        assert!(wide.len() <= MAX_LOGGED_DISPLAY_BYTES + "...".len());
        assert!(wide.trim_end_matches("...").chars().all(|c| c == '€'));
    }

    /// Writes on after a write has failed, and reports success.
    struct Careless(String);

    impl fmt::Display for Careless {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let _ = f.write_str(&self.0);
            let _ = f.write_str("tail");
            Ok(())
        }
    }

    #[test]
    fn bounded_ends_at_the_cut_whatever_the_value_does_next() {
        // The cut falls inside the last of these, with bytes left over for
        // the short writes that follow it.
        let wide = "€".repeat(MAX_LOGGED_DISPLAY_BYTES / 3 + 1);
        let kept = "€".repeat(MAX_LOGGED_DISPLAY_BYTES / 3);
        assert_eq!(bounded(Careless(wide)).to_string(), format!("{kept}..."));
    }

    fn log(writer: &NonBlocking, record: &str) {
        let _ = writer.make_writer().write_all(record.as_bytes());
    }

    #[test]
    fn non_blocking_writer_writes_records_in_order() -> io::Result<()> {
        let written = CapturedLogs::default();
        let (writer, guard) = NonBlocking::spawn(written.clone(), 1024)?;

        log(&writer, "one\n");
        log(&writer, "two\n");
        drop(guard);

        assert_eq!(written.records(), ["one", "two"]);
        Ok(())
    }

    /// A sink whose writes wait until `release` is dropped, or 10s.
    struct HeldSink {
        written: CapturedLogs,
        release: mpsc::Receiver<()>,
    }

    impl Write for HeldSink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let _ = self.release.recv_timeout(Duration::from_secs(10));
            self.written.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn non_blocking_writer_drops_records_instead_of_waiting_for_the_sink() -> io::Result<()> {
        let written = CapturedLogs::default();
        let (release, held) = mpsc::channel();
        let sink = HeldSink {
            written: written.clone(),
            release: held,
        };
        let (writer, guard) = NonBlocking::spawn(sink, 100)?;

        let start = std::time::Instant::now();
        // The sink holds this one, and its bytes count until it is written.
        log(&writer, &format!("{}\n", "a".repeat(59)));
        // No room beside it.
        log(&writer, &format!("{}\n", "b".repeat(59)));
        // Room for this one.
        log(&writer, &format!("{}\n", "c".repeat(29)));
        // Never fits.
        log(&writer, &format!("{}\n", "d".repeat(200)));
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "logging must not wait for the sink"
        );

        drop(release);
        drop(guard);
        assert_eq!(written.records(), ["a".repeat(59), "c".repeat(29)]);
        Ok(())
    }
}
