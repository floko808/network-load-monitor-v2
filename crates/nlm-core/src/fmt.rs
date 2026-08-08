//! Human-readable formatting for the table and status lines.

/// Byte totals in binary units (1024-based), one decimal.
pub fn fmt_bytes(n: f64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.1} {}", UNITS[i])
}

/// Throughput in SI units (1000-based), three decimals.
///
/// Deliberately more precise than [`fmt_bytes`]: a link-load percentage is
/// only as trustworthy as the rate it came from, and operators compare these
/// values against engineered budgets where the third decimal matters.
pub fn fmt_bits(bits_per_s: f64) -> String {
    const UNITS: [&str; 4] = ["bit/s", "Kbit/s", "Mbit/s", "Gbit/s"];
    let mut v = bits_per_s;
    let mut i = 0;
    while v >= 1000.0 && i < UNITS.len() - 1 {
        v /= 1000.0;
        i += 1;
    }
    format!("{v:.3} {}", UNITS[i])
}

/// Link load as a percentage, keeping roughly three significant digits.
///
/// A fixed two decimals is useless here. Station-bus traffic is routinely a
/// few thousandths of a percent of an engineered link — GOOSE and PTP
/// background chatter on a 100 Mb/s link sits around 0.01% — so every row
/// rounds to `0.00` while their total rounds to `0.01`, which reads as a
/// broken column rather than a quiet network. Scaling the precision keeps
/// small loads legible without cluttering a link that is actually busy.
pub fn fmt_pct(pct: f64) -> String {
    if !pct.is_finite() {
        return "-".to_string();
    }
    let p = pct.abs();
    let text = if p == 0.0 {
        return "0.00".to_string();
    } else if p >= 10.0 {
        format!("{pct:.2}")
    } else if p >= 1.0 {
        format!("{pct:.3}")
    } else if p >= 0.01 {
        format!("{pct:.4}")
    } else if p >= 0.0001 {
        format!("{pct:.6}")
    } else {
        // Below a ten-thousandth of the link the exact figure stops
        // mattering; "almost nothing, but not nothing" is the useful
        // statement, and it stays distinct from a true zero.
        return "<0.0001".to_string();
    };
    trim_trailing_zeros(&text, 2)
}

/// Drop trailing zeros, never going below `min_decimals` decimal places.
///
/// The precision bands above are chosen for the smallest value in each band,
/// so a round number lands with padding it does not need — `0.0100` where
/// `0.01` says the same thing more clearly.
fn trim_trailing_zeros(s: &str, min_decimals: usize) -> String {
    let Some(dot) = s.find('.') else {
        return s.to_string();
    };
    let floor = dot + 1 + min_decimals;
    let mut end = s.len();
    while end > floor && s.as_bytes()[end - 1] == b'0' {
        end -= 1;
    }
    s[..end].to_string()
}

/// Elapsed seconds as `HH:MM:SS`.
pub fn fmt_hms(secs: f64) -> String {
    let total = secs.max(0.0) as u64;
    format!("{:02}:{:02}:{:02}", total / 3600, (total % 3600) / 60, total % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_use_binary_units() {
        assert_eq!(fmt_bytes(0.0), "0.0 B");
        assert_eq!(fmt_bytes(1023.0), "1023.0 B");
        assert_eq!(fmt_bytes(1024.0), "1.0 KB");
        assert_eq!(fmt_bytes(1024.0 * 1024.0 * 1.5), "1.5 MB");
    }

    #[test]
    fn bits_use_si_units_with_three_decimals() {
        assert_eq!(fmt_bits(0.0), "0.000 bit/s");
        assert_eq!(fmt_bits(999.0), "999.000 bit/s");
        assert_eq!(fmt_bits(1000.0), "1.000 Kbit/s");
        assert_eq!(fmt_bits(12_345_678.0), "12.346 Mbit/s");
    }

    /// The case from a real substation capture: 11.864 Kbit/s on a 100 Mb/s
    /// link. Two fixed decimals reported this as "0.01" while every
    /// contributing row showed "0.00".
    #[test]
    fn small_loads_stay_legible() {
        assert_eq!(fmt_pct(0.011864), "0.0119");
        assert_eq!(fmt_pct(0.004119), "0.004119");
        assert_eq!(fmt_pct(0.001031), "0.001031");
        // Rows and their subtotal must no longer collapse to the same "0.00".
        assert_ne!(fmt_pct(0.004119), fmt_pct(0.001031));
    }

    #[test]
    fn busy_links_stay_uncluttered() {
        assert_eq!(fmt_pct(20.491), "20.49");
        assert_eq!(fmt_pct(100.0), "100.00");
        assert_eq!(fmt_pct(3.8712), "3.871");
        assert_eq!(fmt_pct(0.3871), "0.3871");
    }

    #[test]
    fn round_values_are_not_padded_with_noise() {
        assert_eq!(fmt_pct(0.01), "0.01");
        assert_eq!(fmt_pct(1.0), "1.00");
        assert_eq!(fmt_pct(50.0), "50.00");
        assert_eq!(fmt_pct(0.5), "0.50");
    }

    #[test]
    fn zero_and_vanishing_loads_are_distinguished() {
        assert_eq!(fmt_pct(0.0), "0.00");
        assert_eq!(fmt_pct(0.00000001), "<0.0001");
        assert_eq!(fmt_pct(f64::NAN), "-");
    }

    #[test]
    fn hms_wraps_correctly() {
        assert_eq!(fmt_hms(0.0), "00:00:00");
        assert_eq!(fmt_hms(3661.0), "01:01:01");
        assert_eq!(fmt_hms(-5.0), "00:00:00");
    }
}
