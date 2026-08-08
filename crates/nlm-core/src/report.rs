//! Turning a [`Snapshot`] into the rows both front ends draw.
//!
//! The original Python carried this logic twice — once in the terminal UI and
//! once in the desktop UI — which is how the two drifted apart on details like
//! subtotal placement. Here the row set, the ordering, the subtotals and the
//! grand total are computed exactly once; a front end only decides how a
//! [`Row`] is painted.

use crate::fmt::{fmt_bits, fmt_pct};
use crate::parse::{Protocol, NONE_STR, PROTO_ORDER};
use crate::stats::{Counter, KeyMap, Snapshot, StatKey};
use std::collections::{BTreeSet, HashMap};

/// Table columns, in display order.
pub const COLUMNS: [&str; 11] = [
    "Protocol",
    "VLAN",
    "CoS",
    "Redundancy",
    "AppID",
    "SVID/GOID",
    "noASDU/stNum",
    "confRev",
    "Sim",
    "bits/s",
    "%",
];

pub const COL_PROTOCOL: usize = 0;
pub const COL_VLAN: usize = 1;
pub const COL_REDUNDANCY: usize = 3;
pub const COL_APPID: usize = 4;
pub const COL_SVID: usize = 5;

/// Columns that get an interactive value filter in the GUI.
pub const FILTERABLE_COLUMNS: [usize; 5] =
    [COL_PROTOCOL, COL_VLAN, COL_REDUNDANCY, COL_APPID, COL_SVID];

/// Load percentage at or above which a rate is shown as critical.
pub const LOAD_CRITICAL_PCT: f64 = 70.0;
/// Load percentage at or above which a rate is shown as elevated.
pub const LOAD_WARN_PCT: f64 = 40.0;

/// How prominently a rate should read.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LoadLevel {
    Normal,
    Warn,
    Critical,
}

impl LoadLevel {
    pub fn of(pct: f64) -> LoadLevel {
        if pct > LOAD_CRITICAL_PCT {
            LoadLevel::Critical
        } else if pct > LOAD_WARN_PCT {
            LoadLevel::Warn
        } else {
            LoadLevel::Normal
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RowKind {
    /// One distinct VLAN/redundancy/AppID combination of a protocol.
    Detail,
    /// A protocol seen earlier but silent in this window.
    Idle,
    /// `Sum <protocol>` across that protocol's detail rows.
    Subtotal,
    /// Everything not broken out individually.
    Other,
    /// The grand total.
    Total,
}

#[derive(Clone, Debug)]
pub struct Row {
    pub kind: RowKind,
    pub cells: [String; COLUMNS.len()],
    /// Link load, or `None` for an idle row where a rate would be misleading.
    pub load_pct: Option<f64>,
    pub bits_per_s: f64,
    /// Frame carried the simulation flag — operationally important to notice.
    pub sim: bool,
    pub redundant: bool,
}

impl Row {
    pub fn load_level(&self) -> LoadLevel {
        self.load_pct.map(LoadLevel::of).unwrap_or(LoadLevel::Normal)
    }
}

/// Post-hoc filter over already-captured data, driven by the GUI's column
/// dropdowns. Distinct from [`crate::filter::FrameFilter`], which drops frames
/// before they are ever counted.
#[derive(Clone, Debug, Default)]
pub struct DisplayFilter {
    /// Column index -> the set of values allowed. Absent means unconstrained.
    cols: HashMap<usize, BTreeSet<String>>,
}

impl DisplayFilter {
    pub fn is_empty(&self) -> bool {
        self.cols.is_empty()
    }

    pub fn is_active(&self, col: usize) -> bool {
        self.cols.contains_key(&col)
    }

    pub fn allowed(&self, col: usize) -> Option<&BTreeSet<String>> {
        self.cols.get(&col)
    }

    /// Constrain a column, or clear it when `values` is `None`.
    pub fn set(&mut self, col: usize, values: Option<BTreeSet<String>>) {
        match values {
            Some(v) => {
                self.cols.insert(col, v);
            }
            None => {
                self.cols.remove(&col);
            }
        }
    }

    pub fn clear(&mut self) {
        self.cols.clear();
    }

    fn allows(&self, cells: &[String; COLUMNS.len()]) -> bool {
        self.cols.iter().all(|(col, allowed)| allowed.contains(&cells[*col]))
    }
}

/// A rendered table plus the figures for the surrounding header and footer.
#[derive(Clone, Debug)]
pub struct Report {
    pub rows: Vec<Row>,
    pub packets: u64,
    pub bytes: u64,
    pub window_secs: f64,
    pub uptime_secs: f64,
    pub is_session_total: bool,
    /// Every distinct value seen per filterable column, for populating the
    /// GUI's dropdowns.
    pub seen_values: HashMap<usize, BTreeSet<String>>,
}

/// Build the table for one snapshot.
///
/// `enabled` selects which protocols are broken out of `Other`; `link_mbps`
/// is the engineered link speed the load percentage is measured against.
pub fn build_report(
    snap: &Snapshot,
    enabled: &BTreeSet<Protocol>,
    link_mbps: f64,
    display_filter: &DisplayFilter,
) -> Report {
    let window = snap.window_secs.max(0.001);
    let link_bits = (link_mbps * 1_000_000.0).max(1.0);
    let rate = |bytes: u64| (bytes as f64) * 8.0 / window;
    let pct = |bits: f64| bits / link_bits * 100.0;

    let mut rows: Vec<Row> = Vec::new();
    let mut seen: HashMap<usize, BTreeSet<String>> = HashMap::new();
    let mut grand = Counter::default();
    let mut other = Counter::default();

    for proto in PROTO_ORDER {
        if !enabled.contains(&proto) {
            // Not broken out: its traffic belongs to the Other row.
            if let Some(keys) = snap.stats.get(&proto) {
                for c in keys.values() {
                    other.packets += c.packets;
                    other.bytes += c.bytes;
                }
            }
            continue;
        }

        let empty = KeyMap::new();
        let keys = snap.stats.get(&proto).unwrap_or(&empty);
        if keys.is_empty() {
            // Silent this window. Keep the last known rows visible rather
            // than letting the protocol disappear, which would be
            // indistinguishable from never having been detected at all.
            if let Some((_, last, since)) = snap.idle.iter().find(|(p, _, _)| *p == proto) {
                let mut idle: Vec<&StatKey> = last.keys().collect();
                idle.sort_by_cached_key(|k| sort_key(k));
                for key in idle {
                    let mut cells = key_cells(proto, key);
                    cells[9] = fmt_bits(0.0);
                    cells[10] = format!("idle {}s", *since as u64);
                    record_seen(&mut seen, &cells);
                    if !display_filter.allows(&cells) {
                        continue;
                    }
                    rows.push(Row {
                        kind: RowKind::Idle,
                        cells,
                        load_pct: None,
                        bits_per_s: 0.0,
                        sim: key.app.is_sim(),
                        redundant: key.redundancy != crate::parse::Redundancy::None,
                    });
                }
            }
            continue;
        }

        let mut sorted: Vec<(&StatKey, &Counter)> = keys.iter().collect();
        sorted.sort_by_cached_key(|(k, _)| sort_key(k));

        let mut subtotal = Counter::default();
        let mut shown = 0usize;
        for (key, count) in sorted {
            let bits = rate(count.bytes);
            let mut cells = key_cells(proto, key);
            cells[9] = fmt_bits(bits);
            cells[10] = fmt_pct(pct(bits));
            record_seen(&mut seen, &cells);
            if !display_filter.allows(&cells) {
                continue;
            }
            shown += 1;
            subtotal.merge_counts(*count);
            rows.push(Row {
                kind: RowKind::Detail,
                cells,
                load_pct: Some(pct(bits)),
                bits_per_s: bits,
                sim: key.app.is_sim(),
                redundant: key.redundancy != crate::parse::Redundancy::None,
            });
        }

        // A subtotal only says something when there is more than one row to sum.
        if shown > 1 {
            let bits = rate(subtotal.bytes);
            let mut cells = blank_cells();
            cells[0] = format!("Sum {}", proto.name());
            cells[9] = fmt_bits(bits);
            cells[10] = fmt_pct(pct(bits));
            rows.push(Row {
                kind: RowKind::Subtotal,
                cells,
                load_pct: Some(pct(bits)),
                bits_per_s: bits,
                sim: false,
                redundant: false,
            });
        }
        grand.merge_counts(subtotal);
    }

    // Every protocol that never gets its own row.
    for (proto, keys) in &snap.stats {
        if PROTO_ORDER.contains(proto) {
            continue;
        }
        for c in keys.values() {
            other.packets += c.packets;
            other.bytes += c.bytes;
        }
    }

    if other.bytes > 0 {
        let bits = rate(other.bytes);
        let mut cells = blank_cells();
        cells[0] = Protocol::Other.name().to_string();
        cells[9] = fmt_bits(bits);
        cells[10] = fmt_pct(pct(bits));
        record_seen(&mut seen, &cells);
        if display_filter.allows(&cells) {
            grand.merge_counts(other);
            rows.push(Row {
                kind: RowKind::Other,
                cells,
                load_pct: Some(pct(bits)),
                bits_per_s: bits,
                sim: false,
                redundant: false,
            });
        }
    }

    let bits = rate(grand.bytes);
    let mut cells = blank_cells();
    cells[0] = "TOTAL".to_string();
    cells[9] = fmt_bits(bits);
    cells[10] = fmt_pct(pct(bits));
    rows.push(Row {
        kind: RowKind::Total,
        cells,
        load_pct: Some(pct(bits)),
        bits_per_s: bits,
        sim: false,
        redundant: false,
    });

    Report {
        rows,
        packets: snap.packets,
        bytes: snap.bytes,
        window_secs: window,
        uptime_secs: snap.uptime_secs,
        is_session_total: snap.is_session_total,
        seen_values: seen,
    }
}

impl Counter {
    fn merge_counts(&mut self, other: Counter) {
        self.packets += other.packets;
        self.bytes += other.bytes;
    }
}

fn blank_cells() -> [String; COLUMNS.len()] {
    std::array::from_fn(|i| if i == 0 { String::new() } else { NONE_STR.to_string() })
}

fn key_cells(proto: Protocol, key: &StatKey) -> [String; COLUMNS.len()] {
    [
        proto.name().to_string(),
        key.vlans.vlan_label(),
        key.vlans.cos_label(),
        key.redundancy.to_string(),
        key.app.appid_label(),
        key.app.svid_label(),
        key.app.noasdu_label(),
        key.app.confrev_label(),
        key.app.sim_label(),
        String::new(),
        String::new(),
    ]
}

/// Stable ordering for rows within a protocol.
fn sort_key(k: &StatKey) -> (Vec<u16>, String, u32, String, u64, u64) {
    (
        k.vlans.ids().to_vec(),
        k.redundancy.to_string(),
        k.app.appid.map(u32::from).unwrap_or(u32::MAX),
        k.app.svid.as_ref().map(|s| s.to_string()).unwrap_or_default(),
        k.app.noasdu.unwrap_or(u64::MAX),
        k.app.confrev.unwrap_or(u64::MAX),
    )
}

fn record_seen(seen: &mut HashMap<usize, BTreeSet<String>>, cells: &[String; COLUMNS.len()]) {
    for col in FILTERABLE_COLUMNS {
        seen.entry(col).or_default().insert(cells[col].clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse_frame;
    use crate::stats::Stats;

    fn goose(vlan: u16, appid: u16) -> crate::parse::Frame {
        let mut raw = vec![0xFFu8; 12];
        raw.extend_from_slice(&[0x81, 0x00, (vlan >> 8) as u8 & 0x0F, (vlan & 0xFF) as u8]);
        raw.extend_from_slice(&[0x88, 0xB8]);
        raw.extend_from_slice(&appid.to_be_bytes());
        raw.extend_from_slice(&[0x00, 0x20, 0x00, 0x00, 0x00, 0x00]);
        raw.extend_from_slice(&[0x61, 0x05, 0x83, 0x03, b'G', b'O', b'1']);
        parse_frame(&raw)
    }

    fn ptp() -> crate::parse::Frame {
        let mut raw = vec![0xFFu8; 12];
        raw.extend_from_slice(&[0x88, 0xF7, 0x00, 0x00]);
        parse_frame(&raw)
    }

    fn enabled(protos: &[Protocol]) -> BTreeSet<Protocol> {
        protos.iter().copied().collect()
    }

    /// 1250 bytes over a 1 s window on a 100 Mb/s link is exactly 0.01%.
    #[test]
    fn computes_rate_and_load_percentage() {
        let s = Stats::new();
        s.record(&goose(11, 0x4041), 1250);
        s.rotate();
        let mut snap = s.snapshot();
        snap.window_secs = 1.0;

        let r = build_report(&snap, &enabled(&[Protocol::Goose]), 100.0, &DisplayFilter::default());
        let detail = &r.rows[0];
        assert_eq!(detail.kind, RowKind::Detail);
        assert_eq!(detail.cells[9], "10.000 Kbit/s");
        assert_eq!(detail.cells[10], "0.01");
    }

    #[test]
    fn adds_a_subtotal_only_when_a_protocol_spans_multiple_rows() {
        let s = Stats::new();
        s.record(&goose(11, 0x4041), 100);
        s.rotate();
        let mut snap = s.snapshot();
        snap.window_secs = 1.0;
        let r = build_report(&snap, &enabled(&[Protocol::Goose]), 100.0, &DisplayFilter::default());
        assert!(!r.rows.iter().any(|row| row.kind == RowKind::Subtotal));

        let s = Stats::new();
        s.record(&goose(11, 0x4041), 100);
        s.record(&goose(12, 0x4042), 100);
        s.rotate();
        let mut snap = s.snapshot();
        snap.window_secs = 1.0;
        let r = build_report(&snap, &enabled(&[Protocol::Goose]), 100.0, &DisplayFilter::default());
        let sub: Vec<&Row> = r.rows.iter().filter(|row| row.kind == RowKind::Subtotal).collect();
        assert_eq!(sub.len(), 1);
        assert_eq!(sub[0].cells[0], "Sum GOOSE");
        assert_eq!(sub[0].bits_per_s, 1600.0);
    }

    #[test]
    fn disabled_protocols_fold_into_other() {
        let s = Stats::new();
        s.record(&goose(11, 0x4041), 100);
        s.record(&ptp(), 100);
        s.rotate();
        let mut snap = s.snapshot();
        snap.window_secs = 1.0;

        // Nothing enabled: both protocols collapse into a single Other row.
        let r = build_report(&snap, &BTreeSet::new(), 100.0, &DisplayFilter::default());
        let other: Vec<&Row> = r.rows.iter().filter(|row| row.kind == RowKind::Other).collect();
        assert_eq!(other.len(), 1);
        assert_eq!(other[0].bits_per_s, 1600.0);
        assert!(!r.rows.iter().any(|row| row.kind == RowKind::Detail));

        // Enabling GOOSE moves only GOOSE out of Other.
        let r = build_report(&snap, &enabled(&[Protocol::Goose]), 100.0, &DisplayFilter::default());
        assert_eq!(r.rows.iter().filter(|row| row.kind == RowKind::Detail).count(), 1);
        let other: Vec<&Row> = r.rows.iter().filter(|row| row.kind == RowKind::Other).collect();
        assert_eq!(other[0].bits_per_s, 800.0);
    }

    #[test]
    fn total_is_the_last_row_and_sums_everything_shown() {
        let s = Stats::new();
        s.record(&goose(11, 0x4041), 100);
        s.record(&ptp(), 300);
        s.rotate();
        let mut snap = s.snapshot();
        snap.window_secs = 1.0;
        let r = build_report(&snap, &enabled(&[Protocol::Goose]), 100.0, &DisplayFilter::default());

        let total = r.rows.last().unwrap();
        assert_eq!(total.kind, RowKind::Total);
        assert_eq!(total.cells[0], "TOTAL");
        assert_eq!(total.bits_per_s, 3200.0); // (100 + 300) bytes * 8
    }

    #[test]
    fn idle_protocols_stay_visible_without_a_rate() {
        let s = Stats::new();
        s.record(&goose(11, 0x4041), 100);
        s.rotate();
        s.rotate(); // a window with no traffic at all

        let snap = s.snapshot();
        let r = build_report(&snap, &enabled(&[Protocol::Goose]), 100.0, &DisplayFilter::default());
        let idle: Vec<&Row> = r.rows.iter().filter(|row| row.kind == RowKind::Idle).collect();
        assert_eq!(idle.len(), 1);
        assert_eq!(idle[0].cells[9], "0.000 bit/s");
        assert!(idle[0].cells[10].starts_with("idle "));
        assert_eq!(idle[0].load_pct, None);
    }

    #[test]
    fn display_filter_hides_rows_without_recounting_them() {
        let s = Stats::new();
        s.record(&goose(11, 0x4041), 100);
        s.record(&goose(12, 0x4042), 100);
        s.rotate();
        let mut snap = s.snapshot();
        snap.window_secs = 1.0;

        let mut df = DisplayFilter::default();
        df.set(COL_VLAN, Some(["11".to_string()].into_iter().collect()));
        let r = build_report(&snap, &enabled(&[Protocol::Goose]), 100.0, &df);

        let details: Vec<&Row> = r.rows.iter().filter(|row| row.kind == RowKind::Detail).collect();
        assert_eq!(details.len(), 1);
        assert_eq!(details[0].cells[COL_VLAN], "11");
        // One row left, so no subtotal, and the total reflects only what shows.
        assert!(!r.rows.iter().any(|row| row.kind == RowKind::Subtotal));
        assert_eq!(r.rows.last().unwrap().bits_per_s, 800.0);
        // Both values remain offerable in the dropdown.
        assert_eq!(r.seen_values[&COL_VLAN].len(), 2);
    }

    #[test]
    fn load_levels_follow_the_documented_thresholds() {
        assert_eq!(LoadLevel::of(10.0), LoadLevel::Normal);
        assert_eq!(LoadLevel::of(40.0), LoadLevel::Normal);
        assert_eq!(LoadLevel::of(40.1), LoadLevel::Warn);
        assert_eq!(LoadLevel::of(70.0), LoadLevel::Warn);
        assert_eq!(LoadLevel::of(70.1), LoadLevel::Critical);
    }
}
