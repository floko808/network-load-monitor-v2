//! Pre-count capture filter.
//!
//! Constraints here are applied *before* a frame is counted, so a filtered
//! frame never reaches the table, the running totals or the session summary.
//! This is what makes the CLI's filter flags useful for unattended runs: the
//! memory and the output only ever hold traffic that was asked for.
//!
//! The GUI's column dropdowns are a different mechanism entirely — those
//! filter what is *displayed* from data already captured.

use crate::parse::{Frame, Redundancy};
use std::collections::BTreeSet;
use std::fmt::Write as _;

/// Redundancy tokens accepted by `--redundancy`.
pub const REDUNDANCY_TOKENS: [&str; 7] =
    ["hsr", "prp", "none", "hsr-a", "hsr-b", "prp-a", "prp-b"];

/// A predicate over four independent, all-optional constraints.
///
/// Values within one field are OR'd; different fields are AND'd. `None` means
/// the field places no constraint at all.
#[derive(Clone, Debug, Default)]
pub struct FrameFilter {
    pub vlans: Option<BTreeSet<u16>>,
    pub redundancy: Option<BTreeSet<String>>,
    pub appids: Option<BTreeSet<u16>>,
    /// Matches the shared SVID/goID column; `--goid` and `--svid` both feed it.
    pub svids: Option<BTreeSet<String>>,
}

impl FrameFilter {
    pub fn is_empty(&self) -> bool {
        self.vlans.is_none()
            && self.redundancy.is_none()
            && self.appids.is_none()
            && self.svids.is_none()
    }

    pub fn matches(&self, frame: &Frame) -> bool {
        if let Some(want) = &self.vlans {
            // Any tag in a stacked (QinQ) frame may satisfy the constraint,
            // not just the outermost one.
            if !frame.vlans.ids().iter().any(|id| want.contains(id)) {
                return false;
            }
        }
        if let Some(want) = &self.redundancy {
            if !redundancy_tokens(frame.redundancy).iter().any(|t| want.contains(*t)) {
                return false;
            }
        }
        if let Some(want) = &self.appids {
            match frame.app.appid {
                Some(a) if want.contains(&a) => {}
                _ => return false,
            }
        }
        if let Some(want) = &self.svids {
            match &frame.app.svid {
                Some(s) if want.contains(&s.to_uppercase()) => {}
                _ => return false,
            }
        }
        true
    }

    /// One-line description for the panel footer, empty when no filter is set.
    pub fn summary(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if let Some(v) = &self.vlans {
            parts.push(format!("vlan={}", join(v.iter().map(|x| x.to_string()))));
        }
        if let Some(v) = &self.redundancy {
            parts.push(format!("redundancy={}", join(v.iter().cloned())));
        }
        if let Some(v) = &self.appids {
            parts.push(format!("appid={}", join(v.iter().map(|x| format!("0x{x:04X}")))));
        }
        if let Some(v) = &self.svids {
            parts.push(format!("id={}", join(v.iter().cloned())));
        }
        parts.join(" ")
    }
}

fn join(items: impl Iterator<Item = String>) -> String {
    let mut out = String::new();
    for (i, s) in items.enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(out, "{s}");
    }
    out
}

/// The tokens a frame's redundancy state satisfies.
///
/// A two-token result is what lets `--redundancy hsr` match either lane while
/// `--redundancy hsr-a` stays specific to one.
fn redundancy_tokens(r: Redundancy) -> Vec<&'static str> {
    match r {
        Redundancy::None => vec!["none"],
        Redundancy::Hsr(0xA) => vec!["hsr", "hsr-a"],
        Redundancy::Hsr(0xB) => vec!["hsr", "hsr-b"],
        Redundancy::Hsr(_) => vec!["hsr"],
        Redundancy::Prp(0xA) => vec!["prp", "prp-a"],
        Redundancy::Prp(0xB) => vec!["prp", "prp-b"],
        Redundancy::Prp(_) => vec!["prp"],
    }
}

/// Parse a comma-separated `--vlan` value.
pub fn parse_vlans(s: &str) -> Result<BTreeSet<u16>, String> {
    split(s)
        .map(|v| {
            v.parse::<u16>()
                .ok()
                .filter(|id| *id <= 4095)
                .ok_or_else(|| format!("invalid VLAN id '{v}' (expected 0-4095)"))
        })
        .collect()
}

/// Parse a comma-separated `--appid` value; hex, with or without `0x`.
pub fn parse_appids(s: &str) -> Result<BTreeSet<u16>, String> {
    split(s)
        .map(|v| {
            let t = v.trim_start_matches("0x").trim_start_matches("0X");
            u16::from_str_radix(t, 16)
                .map_err(|_| format!("invalid AppID '{v}' (expected hex, e.g. 0x4041)"))
        })
        .collect()
}

/// Parse and validate a comma-separated `--redundancy` value.
pub fn parse_redundancy(s: &str) -> Result<BTreeSet<String>, String> {
    split(s)
        .map(|v| {
            let t = v.to_lowercase();
            if REDUNDANCY_TOKENS.contains(&t.as_str()) {
                Ok(t)
            } else {
                Err(format!(
                    "invalid redundancy value '{v}' (expected one of: {})",
                    REDUNDANCY_TOKENS.join(", ")
                ))
            }
        })
        .collect()
}

/// Parse a comma-separated `--goid` / `--svid` value, normalised for matching.
pub fn parse_ids(s: &str) -> BTreeSet<String> {
    split(s).map(|v| v.to_uppercase()).collect()
}

fn split(s: &str) -> impl Iterator<Item = &str> {
    s.split(',').map(str::trim).filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::{AppInfo, Protocol, VlanTags};

    fn frame(vlans: &[(u16, u8)], redundancy: Redundancy, appid: Option<u16>, svid: Option<&str>) -> Frame {
        Frame {
            proto: Protocol::Goose,
            vlans: VlanTags::from_tags(vlans),
            redundancy,
            app: AppInfo {
                appid,
                svid: svid.map(|s| s.to_string().into_boxed_str()),
                ..Default::default()
            },
        }
    }

    #[test]
    fn empty_filter_accepts_everything() {
        let f = FrameFilter::default();
        assert!(f.is_empty());
        assert!(f.matches(&frame(&[], Redundancy::None, None, None)));
    }

    #[test]
    fn redundancy_scheme_matches_either_lane() {
        let f = FrameFilter { redundancy: Some(parse_redundancy("hsr").unwrap()), ..Default::default() };
        assert!(f.matches(&frame(&[], Redundancy::Hsr(0xA), None, None)));
        assert!(f.matches(&frame(&[], Redundancy::Hsr(0xB), None, None)));
        assert!(!f.matches(&frame(&[], Redundancy::Prp(0xA), None, None)));
        assert!(!f.matches(&frame(&[], Redundancy::None, None, None)));
    }

    #[test]
    fn redundancy_lane_is_specific() {
        let f = FrameFilter { redundancy: Some(parse_redundancy("hsr-a").unwrap()), ..Default::default() };
        assert!(f.matches(&frame(&[], Redundancy::Hsr(0xA), None, None)));
        assert!(!f.matches(&frame(&[], Redundancy::Hsr(0xB), None, None)));
    }

    #[test]
    fn none_token_selects_unredundant_traffic() {
        let f = FrameFilter { redundancy: Some(parse_redundancy("none").unwrap()), ..Default::default() };
        assert!(f.matches(&frame(&[], Redundancy::None, None, None)));
        assert!(!f.matches(&frame(&[], Redundancy::Prp(0xB), None, None)));
    }

    #[test]
    fn fields_are_anded_and_values_ored() {
        let f = FrameFilter {
            vlans: Some(parse_vlans("11,12").unwrap()),
            appids: Some(parse_appids("0x4041").unwrap()),
            ..Default::default()
        };
        assert!(f.matches(&frame(&[(11, 4)], Redundancy::None, Some(0x4041), None)));
        assert!(f.matches(&frame(&[(12, 4)], Redundancy::None, Some(0x4041), None)));
        // VLAN matches but AppID does not -> rejected.
        assert!(!f.matches(&frame(&[(11, 4)], Redundancy::None, Some(0x4042), None)));
        // AppID matches but VLAN does not -> rejected.
        assert!(!f.matches(&frame(&[(13, 4)], Redundancy::None, Some(0x4041), None)));
    }

    #[test]
    fn ids_match_case_insensitively() {
        let f = FrameFilter { svids: Some(parse_ids("myGoose1")), ..Default::default() };
        assert!(f.matches(&frame(&[], Redundancy::None, None, Some("MYGOOSE1"))));
        assert!(f.matches(&frame(&[], Redundancy::None, None, Some("mygoose1"))));
        assert!(!f.matches(&frame(&[], Redundancy::None, None, Some("other"))));
        assert!(!f.matches(&frame(&[], Redundancy::None, None, None)));
    }

    #[test]
    fn rejects_invalid_values_at_parse_time() {
        assert!(parse_vlans("4096").is_err());
        assert!(parse_vlans("abc").is_err());
        assert!(parse_appids("zz").is_err());
        assert!(parse_redundancy("hsr-c").is_err());
        assert_eq!(parse_appids("0x4041").unwrap(), parse_appids("4041").unwrap());
    }
}
