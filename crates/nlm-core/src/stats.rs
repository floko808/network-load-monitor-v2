//! Rolling-window statistics shared by both front ends.
//!
//! Three sets of counters are kept at once, because each answers a question
//! the others cannot:
//!
//! * **current** — the window still filling. Never displayed directly, so the
//!   table can't race a half-collected window and show a dip that isn't real.
//! * **display** — a snapshot of the last *completed* window. This is what
//!   rates and load percentages are computed from.
//! * **session** — cumulative totals for the whole run, never rotated. When a
//!   capture stops, the final window may be empty for a bursty protocol that
//!   carried plenty of traffic earlier; without this there would be nothing
//!   honest to show in a summary.
//!
//! Alongside those, the last *non-empty* window per protocol is retained so a
//! sparse protocol's rows stay on screen between bursts. A row vanishing the
//! instant traffic pauses looks identical to "never detected", which is a
//! materially misleading thing to show an operator.

use crate::parse::{AppInfo, Frame, Protocol, Redundancy, VlanTags};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// Everything that distinguishes one table row from another within a protocol.
///
/// Two frames of the same protocol that differ in any of these get separate
/// rows, each accumulating its own byte count.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct StatKey {
    pub vlans: VlanTags,
    pub redundancy: Redundancy,
    pub app: AppInfo,
}

impl From<&Frame> for StatKey {
    fn from(f: &Frame) -> Self {
        StatKey { vlans: f.vlans, redundancy: f.redundancy, app: f.app.clone() }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counter {
    pub packets: u64,
    pub bytes: u64,
}

impl Counter {
    fn add(&mut self, bytes: u64) {
        self.packets += 1;
        self.bytes += bytes;
    }

    fn merge(&mut self, other: Counter) {
        self.packets += other.packets;
        self.bytes += other.bytes;
    }
}

pub type KeyMap = HashMap<StatKey, Counter>;
pub type StatsMap = HashMap<Protocol, KeyMap>;

fn merge_into(dst: &mut StatsMap, src: &StatsMap) {
    for (proto, keys) in src {
        let entry = dst.entry(*proto).or_default();
        for (key, count) in keys {
            entry.entry(key.clone()).or_default().merge(*count);
        }
    }
}

/// A thread-local pre-aggregator sitting in front of the shared engine.
///
/// Capture threads fold frames in here without touching a lock, and hand the
/// whole batch over at once. At Sampled Values rates a stream collapses to a
/// single key, so 200 frames become one merge under lock instead of 200.
pub struct BatchAccum {
    map: StatsMap,
    packets: u64,
    bytes: u64,
    count: usize,
    since: Instant,
    max_pkts: usize,
    max_secs: f64,
    span: TimeSpan,
}

impl BatchAccum {
    pub fn new(max_pkts: usize, max_secs: f64) -> Self {
        BatchAccum {
            map: StatsMap::new(),
            packets: 0,
            bytes: 0,
            count: 0,
            since: Instant::now(),
            max_pkts,
            max_secs,
            span: TimeSpan::default(),
        }
    }

    /// Fold one frame in. Returns `true` when the batch is ready to flush.
    ///
    /// The time bound matters as much as the packet bound: on a quiet network
    /// waiting for 200 frames could stall the display for minutes.
    ///
    /// `ts` is the frame's own capture timestamp where the backend provides
    /// one. It is what keeps rates honest when frames reach us in bursts
    /// rather than as they were captured.
    pub fn push(&mut self, frame: &Frame, size: u64, ts: Option<f64>) -> bool {
        self.map
            .entry(frame.proto)
            .or_default()
            .entry(StatKey::from(frame))
            .or_default()
            .add(size);
        self.packets += 1;
        self.bytes += size;
        self.count += 1;
        self.span.observe(ts);
        self.is_full()
    }

    pub fn is_full(&self) -> bool {
        self.count >= self.max_pkts || self.since.elapsed().as_secs_f64() >= self.max_secs
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Take the accumulated batch, resetting for the next one.
    pub fn take(&mut self) -> Batch {
        self.count = 0;
        self.since = Instant::now();
        Batch {
            stats: std::mem::take(&mut self.map),
            packets: std::mem::take(&mut self.packets),
            bytes: std::mem::take(&mut self.bytes),
            span: std::mem::take(&mut self.span),
        }
    }
}

/// One completed batch handed from a capture thread to the shared engine.
#[derive(Debug, Default)]
pub struct Batch {
    pub stats: StatsMap,
    pub packets: u64,
    pub bytes: u64,
    pub span: TimeSpan,
}

/// The range of capture timestamps covered by some set of frames.
///
/// Empty when the backend supplies no timestamps, which is the normal case
/// for the raw-socket path where arrival time already is capture time.
#[derive(Clone, Copy, Debug, Default)]
pub struct TimeSpan {
    min: Option<f64>,
    max: Option<f64>,
}

impl TimeSpan {
    fn observe(&mut self, ts: Option<f64>) {
        let Some(t) = ts.filter(|t| t.is_finite() && *t > 0.0) else {
            return;
        };
        self.min = Some(self.min.map_or(t, |m: f64| m.min(t)));
        self.max = Some(self.max.map_or(t, |m: f64| m.max(t)));
    }

    fn merge(&mut self, other: TimeSpan) {
        self.observe(other.min);
        self.observe(other.max);
    }

    /// Seconds between the earliest and latest frame, if known.
    fn seconds(&self) -> Option<f64> {
        match (self.min, self.max) {
            (Some(a), Some(b)) if b > a => Some(b - a),
            _ => None,
        }
    }
}

struct Inner {
    cur: StatsMap,
    disp: StatsMap,
    session: StatsMap,
    last_active: HashMap<Protocol, KeyMap>,
    last_active_at: HashMap<Protocol, Instant>,
    win_start: Instant,
    win_dur: f64,
    /// Capture-timestamp range of the frames in the window still filling.
    cur_span: TimeSpan,
    packets: u64,
    bytes: u64,
}

/// The shared statistics engine. Cheap to share across threads via `Arc`.
pub struct Stats {
    inner: Mutex<Inner>,
    started: Instant,
}

impl Default for Stats {
    fn default() -> Self {
        Self::new()
    }
}

impl Stats {
    pub fn new() -> Self {
        let now = Instant::now();
        Stats {
            inner: Mutex::new(Inner {
                cur: StatsMap::new(),
                disp: StatsMap::new(),
                session: StatsMap::new(),
                last_active: HashMap::new(),
                last_active_at: HashMap::new(),
                win_start: now,
                win_dur: 0.001,
                cur_span: TimeSpan::default(),
                packets: 0,
                bytes: 0,
            }),
            started: now,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A panic in a frame handler must not take the whole capture down;
        // the counters are plain numbers and stay usable either way.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Merge a completed batch from a capture thread.
    pub fn merge_batch(&self, batch: &Batch) {
        let mut inner = self.lock();
        merge_into(&mut inner.cur, &batch.stats);
        merge_into(&mut inner.session, &batch.stats);
        inner.cur_span.merge(batch.span);
        inner.packets += batch.packets;
        inner.bytes += batch.bytes;
    }

    /// Record a single frame directly, for low-rate backends where batching
    /// would only add latency.
    pub fn record(&self, frame: &Frame, size: u64) {
        let mut inner = self.lock();
        let key = StatKey::from(frame);
        inner.cur.entry(frame.proto).or_default().entry(key.clone()).or_default().add(size);
        inner.session.entry(frame.proto).or_default().entry(key).or_default().add(size);
        inner.packets += 1;
        inner.bytes += size;
    }

    /// Close the current window and promote it to the displayed one.
    pub fn rotate(&self) {
        let now = Instant::now();
        let mut inner = self.lock();

        // Rates divide by whichever is longer: the wall-clock window, or the
        // stretch of capture time the frames themselves cover.
        //
        // Those differ whenever a backend delivers frames in bursts rather
        // than as they were captured — which is exactly what a `dumpcap` pipe
        // does, and on Windows that is the only backend there is. Ten seconds
        // of buffered traffic arriving in one read would otherwise be divided
        // by a one-second window and reported at ten times the real load.
        // Taking the longer of the two also keeps a sparse window honest: two
        // frames a millisecond apart are a trickle over that second, not a
        // burst measured over a millisecond.
        let wall = (now - inner.win_start).as_secs_f64();
        let covered = inner.cur_span.seconds().unwrap_or(0.0);
        inner.win_dur = wall.max(covered).max(0.001);
        inner.win_start = now;
        inner.cur_span = TimeSpan::default();
        inner.disp = std::mem::take(&mut inner.cur);

        let active: Vec<(Protocol, KeyMap)> = inner
            .disp
            .iter()
            .filter(|(_, keys)| !keys.is_empty())
            .map(|(p, keys)| (*p, keys.clone()))
            .collect();
        for (proto, keys) in active {
            inner.last_active.insert(proto, keys);
            inner.last_active_at.insert(proto, now);
        }
    }

    /// A consistent view of the last completed window, for rendering.
    pub fn snapshot(&self) -> Snapshot {
        let inner = self.lock();
        let now = Instant::now();
        Snapshot {
            stats: inner.disp.clone(),
            idle: idle_rows(&inner, &inner.disp, now),
            window_secs: inner.win_dur,
            packets: inner.packets,
            bytes: inner.bytes,
            uptime_secs: (now - self.started).as_secs_f64(),
            is_session_total: false,
        }
    }

    /// A view of the whole run, used for the final render once capture ends.
    pub fn session_snapshot(&self) -> Snapshot {
        let inner = self.lock();
        let now = Instant::now();
        let uptime = (now - self.started).as_secs_f64();
        Snapshot {
            stats: inner.session.clone(),
            idle: Vec::new(),
            // Rates over the session are computed against its full duration.
            window_secs: uptime.max(0.001),
            packets: inner.packets,
            bytes: inner.bytes,
            uptime_secs: uptime,
            is_session_total: true,
        }
    }

    pub fn totals(&self) -> (u64, u64) {
        let inner = self.lock();
        (inner.packets, inner.bytes)
    }

    pub fn uptime_secs(&self) -> f64 {
        self.started.elapsed().as_secs_f64()
    }

    /// Replace all counters with an already-computed map, as produced by an
    /// offline file load.
    pub fn set_offline(&self, stats: StatsMap, duration_s: f64, packets: u64, bytes: u64) {
        let mut inner = self.lock();
        inner.disp = stats.clone();
        inner.session = stats;
        inner.cur = StatsMap::new();
        inner.last_active.clear();
        inner.last_active_at.clear();
        inner.win_dur = duration_s.max(0.001);
        inner.packets = packets;
        inner.bytes = bytes;
    }
}

/// Protocols that carried traffic recently but not in the current window.
fn idle_rows(inner: &Inner, disp: &StatsMap, now: Instant) -> Vec<(Protocol, KeyMap, f64)> {
    inner
        .last_active
        .iter()
        .filter(|(proto, _)| disp.get(proto).is_none_or(|k| k.is_empty()))
        .map(|(proto, keys)| {
            let since = inner
                .last_active_at
                .get(proto)
                .map(|t| (now - *t).as_secs_f64())
                .unwrap_or(0.0);
            (*proto, keys.clone(), since)
        })
        .collect()
}

/// An immutable view of the statistics, safe to render from without a lock.
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub stats: StatsMap,
    /// `(protocol, last known rows, seconds since last seen)`.
    pub idle: Vec<(Protocol, KeyMap, f64)>,
    /// Seconds the counters in `stats` cover — the divisor for every rate.
    pub window_secs: f64,
    pub packets: u64,
    pub bytes: u64,
    pub uptime_secs: f64,
    /// Whether this covers the whole run rather than one window.
    pub is_session_total: bool,
}

impl Snapshot {
    /// Build a snapshot from an offline load, where the capture's own span
    /// stands in for a live window's elapsed time.
    pub fn offline(stats: StatsMap, duration_s: f64, packets: u64, bytes: u64) -> Snapshot {
        Snapshot {
            stats,
            idle: Vec::new(),
            window_secs: duration_s.max(0.001),
            packets,
            bytes,
            uptime_secs: duration_s,
            is_session_total: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse_frame;

    fn ptp_frame(vlan: Option<u16>) -> Frame {
        let mut raw = vec![0xFFu8; 12];
        if let Some(id) = vlan {
            raw.extend_from_slice(&[0x81, 0x00]);
            raw.extend_from_slice(&[(id >> 8) as u8 & 0x0F, (id & 0xFF) as u8]);
        }
        raw.extend_from_slice(&[0x88, 0xF7, 0x00, 0x00]);
        parse_frame(&raw)
    }

    #[test]
    fn separate_keys_get_separate_rows() {
        let s = Stats::new();
        s.record(&ptp_frame(Some(11)), 100);
        s.record(&ptp_frame(Some(11)), 100);
        s.record(&ptp_frame(Some(12)), 50);
        s.rotate();

        let snap = s.snapshot();
        let rows = &snap.stats[&Protocol::Ptp];
        assert_eq!(rows.len(), 2);
        let total: u64 = rows.values().map(|c| c.bytes).sum();
        assert_eq!(total, 250);
        assert_eq!(snap.packets, 3);
        assert_eq!(snap.bytes, 250);
    }

    #[test]
    fn rotation_moves_current_to_display_and_clears_current() {
        let s = Stats::new();
        s.record(&ptp_frame(None), 64);
        // Nothing is displayed until a window closes.
        assert!(s.snapshot().stats.is_empty());

        s.rotate();
        assert_eq!(s.snapshot().stats[&Protocol::Ptp].len(), 1);

        // A second rotation with no traffic empties the display...
        s.rotate();
        assert!(s.snapshot().stats.get(&Protocol::Ptp).is_none_or(|k| k.is_empty()));
        // ...but the session total still holds it, and it is reported idle.
        assert_eq!(s.session_snapshot().stats[&Protocol::Ptp].len(), 1);
        assert_eq!(s.snapshot().idle.len(), 1);
        assert_eq!(s.snapshot().idle[0].0, Protocol::Ptp);
    }

    #[test]
    fn session_totals_survive_many_rotations() {
        let s = Stats::new();
        for _ in 0..5 {
            s.record(&ptp_frame(None), 100);
            s.rotate();
        }
        let session = s.session_snapshot();
        assert_eq!(session.stats[&Protocol::Ptp].values().map(|c| c.bytes).sum::<u64>(), 500);
        assert_eq!(session.packets, 5);
        assert!(session.is_session_total);
    }

    #[test]
    fn batches_pre_aggregate_before_merging() {
        let s = Stats::new();
        let mut batch = BatchAccum::new(3, 60.0);
        assert!(!batch.push(&ptp_frame(None), 10, None));
        assert!(!batch.push(&ptp_frame(None), 10, None));
        assert!(batch.push(&ptp_frame(None), 10, None)); // full at 3

        let taken = batch.take();
        // Identical frames collapse to one key before the lock is taken.
        assert_eq!(taken.stats[&Protocol::Ptp].len(), 1);
        assert_eq!(taken.packets, 3);
        assert_eq!(taken.bytes, 30);
        assert!(batch.is_empty());

        s.merge_batch(&taken);
        s.rotate();
        let snap = s.snapshot();
        assert_eq!(snap.packets, 3);
        assert_eq!(snap.stats[&Protocol::Ptp].values().next().unwrap().packets, 3);
    }

    /// A backend that buffers must not inflate the reported rate.
    ///
    /// `dumpcap` pipes frames to us in chunks, so a single read can carry
    /// several seconds of traffic. Dividing that by the wall-clock window it
    /// happened to land in would report a multiple of the real link load —
    /// the whole point of the timestamps.
    #[test]
    fn buffered_delivery_is_measured_over_the_time_it_covers() {
        let s = Stats::new();
        let mut batch = BatchAccum::new(1000, 60.0);
        // 10 seconds of capture time delivered in one go.
        for i in 0..10 {
            batch.push(&ptp_frame(None), 1000, Some(1_000_000.0 + i as f64));
        }
        s.merge_batch(&batch.take());
        s.rotate();

        let snap = s.snapshot();
        // The wall-clock window here is near zero; the span is 9 seconds.
        assert!(
            (snap.window_secs - 9.0).abs() < 0.5,
            "expected ~9s of coverage, got {}",
            snap.window_secs
        );
    }

    /// The converse: a couple of frames close together are a trickle across
    /// the window, not a burst measured over the microseconds between them.
    #[test]
    fn sparse_frames_are_measured_over_the_whole_window() {
        let s = Stats::new();
        let mut batch = BatchAccum::new(1000, 60.0);
        batch.push(&ptp_frame(None), 100, Some(1_000_000.000));
        batch.push(&ptp_frame(None), 100, Some(1_000_000.001));
        s.merge_batch(&batch.take());

        std::thread::sleep(std::time::Duration::from_millis(120));
        s.rotate();

        let snap = s.snapshot();
        assert!(
            snap.window_secs >= 0.1,
            "a 1 ms span must not shrink the window to 1 ms: got {}",
            snap.window_secs
        );
    }

    #[test]
    fn timestamps_are_ignored_when_a_backend_supplies_none() {
        let s = Stats::new();
        let mut batch = BatchAccum::new(1000, 60.0);
        batch.push(&ptp_frame(None), 100, None);
        s.merge_batch(&batch.take());
        std::thread::sleep(std::time::Duration::from_millis(60));
        s.rotate();
        // Falls back cleanly to the wall-clock window.
        let w = s.snapshot().window_secs;
        assert!((0.05..5.0).contains(&w), "unexpected window {w}");
    }
}
