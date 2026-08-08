//! Terminal rendering of a [`Report`].
//!
//! Everything drawn here is plain ASCII. A Windows console running a legacy
//! code page cannot encode box-drawing characters, `∑` or `∞`, and rendering
//! one there fails outright rather than degrading to a `?`.

use crossterm::style::{Attribute, Color, Stylize};
use nlm_core::consts::SOFTWARE_NAME;
use nlm_core::fmt::{fmt_bytes, fmt_hms};
use nlm_core::report::{LoadLevel, Report, Row, RowKind, COLUMNS};

/// Per-column tint, matching the column order in [`COLUMNS`].
const COLUMN_COLORS: [Option<Color>; COLUMNS.len()] = [
    Some(Color::Cyan),      // Protocol
    Some(Color::Yellow),    // VLAN
    Some(Color::Blue),      // CoS
    Some(Color::Magenta),   // Redundancy
    Some(Color::Green),     // AppID
    None,                   // SVID/GOID
    None,                   // noASDU/stNum
    Some(Color::Cyan),      // confRev
    None,                   // Sim
    None,                   // bits/s
    None,                   // %
];

/// Columns rendered flush right, where comparing magnitudes matters.
const RIGHT_ALIGNED: [bool; COLUMNS.len()] =
    [false, false, false, false, false, false, true, true, false, true, true];

/// Render the full panel as a list of lines, ready to print.
pub fn render(report: &Report, title_context: &str, footer_extra: &str, width: usize) -> Vec<String> {
    let widths = column_widths(report);
    let mut lines = Vec::new();

    // The table's own width is the floor: narrowing the box below it would
    // push cells past the right border rather than make anything fit. A wider
    // terminal simply expands the panel to fill it.
    let footer = footer_line(report, footer_extra);
    let content = rule_len(&widths).max(visible_len(&footer)).max(40);
    let inner = content.max(width.saturating_sub(4));

    lines.push(top_border(title_context, inner));
    lines.push(bordered(&header_line(&widths), inner));
    lines.push(bordered(&"-".repeat(inner), inner));

    let mut any_rows = false;
    for row in &report.rows {
        // Set the grand total apart from the protocol rows above it.
        if row.kind == RowKind::Total && any_rows {
            lines.push(bordered(&"-".repeat(inner), inner));
        }
        lines.push(bordered(&row_line(row, &widths), inner));
        any_rows = true;
    }

    lines.push(bordered("", inner));
    lines.push(bordered(&footer, inner));
    lines.push(format!("+{}+", "-".repeat(inner + 2)));
    lines
}

fn rule_len(widths: &[usize]) -> usize {
    widths.iter().sum::<usize>() + (widths.len() - 1) * 2
}

fn column_widths(report: &Report) -> Vec<usize> {
    let mut widths: Vec<usize> = COLUMNS.iter().map(|h| h.len()).collect();
    for row in &report.rows {
        for (i, cell) in row.cells.iter().enumerate() {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }
    widths
}

fn top_border(context: &str, inner: usize) -> String {
    let title = format!(" {SOFTWARE_NAME} - {context} ");
    let total = inner + 2;
    if title.len() + 4 >= total {
        return format!("+{}+", "-".repeat(total));
    }
    let after = total - title.len() - 2;
    format!("+-{}{}+", title, "-".repeat(after + 1))
}

fn bordered(content: &str, inner: usize) -> String {
    // Padding is computed on the visible text, before any colour escapes are
    // added, so the right-hand border always lines up.
    let visible = visible_len(content);
    let pad = inner.saturating_sub(visible);
    format!("| {}{} |", content, " ".repeat(pad))
}

/// Length of `s` ignoring ANSI escape sequences.
fn visible_len(s: &str) -> usize {
    let mut n = 0;
    let mut in_escape = false;
    for c in s.chars() {
        if in_escape {
            if c == 'm' {
                in_escape = false;
            }
        } else if c == '\x1b' {
            in_escape = true;
        } else {
            n += 1;
        }
    }
    n
}

fn header_line(widths: &[usize]) -> String {
    let mut out = String::new();
    for (i, head) in COLUMNS.iter().enumerate() {
        if i > 0 {
            out.push_str("  ");
        }
        let text = pad(head, widths[i], RIGHT_ALIGNED[i]);
        out.push_str(&text.with(Color::White).attribute(Attribute::Bold).to_string());
    }
    out
}

fn row_line(row: &Row, widths: &[usize]) -> String {
    let mut out = String::new();
    for (i, cell) in row.cells.iter().enumerate() {
        if i > 0 {
            out.push_str("  ");
        }
        out.push_str(&paint(row, i, cell, widths[i]));
    }
    out
}

fn paint(row: &Row, col: usize, cell: &str, width: usize) -> String {
    let text = pad(cell, width, RIGHT_ALIGNED[col]);

    // Subtotals and idle rows are structurally secondary; keeping them dim
    // stops them competing with the live measurements they summarise.
    if matches!(row.kind, RowKind::Subtotal | RowKind::Idle) {
        return text.with(Color::DarkGrey).to_string();
    }
    if row.kind == RowKind::Total {
        let styled = text.attribute(Attribute::Bold);
        return match (col, row.load_level()) {
            (10, LoadLevel::Critical) => styled.with(Color::Red).to_string(),
            (10, LoadLevel::Warn) => styled.with(Color::Yellow).to_string(),
            _ => styled.to_string(),
        };
    }

    // A frame carrying the simulation flag is not real plant data. It gets
    // the loudest styling in the table for exactly that reason.
    if col == 8 && row.sim {
        return text.with(Color::Red).attribute(Attribute::Bold).to_string();
    }
    if col == 3 && row.redundant {
        return text.with(Color::Magenta).attribute(Attribute::Bold).to_string();
    }
    if col == 10 {
        return match row.load_level() {
            LoadLevel::Critical => text.with(Color::Red).attribute(Attribute::Bold).to_string(),
            LoadLevel::Warn => text.with(Color::Yellow).attribute(Attribute::Bold).to_string(),
            LoadLevel::Normal => text,
        };
    }
    match COLUMN_COLORS[col] {
        Some(c) => text.with(c).to_string(),
        None => text,
    }
}

fn pad(s: &str, width: usize, right: bool) -> String {
    let len = s.chars().count();
    let fill = width.saturating_sub(len);
    if right {
        format!("{}{}", " ".repeat(fill), s)
    } else {
        format!("{}{}", s, " ".repeat(fill))
    }
}

fn footer_line(report: &Report, extra: &str) -> String {
    let mut parts = vec![
        format!("packets {}", report.packets),
        format!("bytes {}", fmt_bytes(report.bytes as f64)),
        format!("uptime {}", fmt_hms(report.uptime_secs)),
    ];
    if report.is_session_total {
        parts.push(format!("session total ({:.0}s)", report.window_secs));
    } else {
        parts.push(format!("window {:.0} ms", report.window_secs * 1000.0));
    }
    if !extra.is_empty() {
        parts.push(extra.to_string());
    }
    parts.join("  ").with(Color::DarkGrey).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use nlm_core::parse::parse_frame;
    use nlm_core::report::{build_report, DisplayFilter};
    use nlm_core::stats::Stats;
    use nlm_core::Protocol;
    use std::collections::BTreeSet;

    fn sample_report() -> Report {
        let mut raw = vec![0xFFu8; 12];
        raw.extend_from_slice(&[0x88, 0xF7, 0x00, 0x00]);
        let frame = parse_frame(&raw);
        let s = Stats::new();
        s.record(&frame, 1000);
        s.rotate();
        let mut snap = s.snapshot();
        snap.window_secs = 1.0;
        let enabled: BTreeSet<Protocol> = BTreeSet::new();
        build_report(&snap, &enabled, 100.0, &DisplayFilter::default())
    }

    #[test]
    fn every_line_is_the_same_visible_width() {
        let lines = render(&sample_report(), "eth0 @ 100 Mb/s", "", 200);
        let widths: Vec<usize> = lines.iter().map(|l| visible_len(l)).collect();
        assert!(widths.windows(2).all(|w| w[0] == w[1]), "ragged panel: {widths:?}");
    }

    #[test]
    fn output_stays_ascii_for_legacy_windows_consoles() {
        let lines = render(&sample_report(), "eth0 @ 100 Mb/s", "filter vlan=11", 200);
        for line in &lines {
            // Strip escapes, then require plain ASCII in what remains.
            let text: String = line.chars().filter(|c| !c.is_control()).collect();
            assert!(text.is_ascii(), "non-ASCII output would break a cp1252 console: {line}");
        }
    }

    #[test]
    fn visible_length_ignores_colour_escapes() {
        let plain = "GOOSE";
        let coloured = plain.with(Color::Cyan).to_string();
        assert!(coloured.len() > plain.len());
        assert_eq!(visible_len(&coloured), 5);
    }

    #[test]
    fn footer_reports_session_totals_distinctly() {
        let mut r = sample_report();
        r.is_session_total = false;
        assert!(footer_line(&r, "").contains("window"));
        r.is_session_total = true;
        assert!(footer_line(&r, "").contains("session total"));
    }
}
