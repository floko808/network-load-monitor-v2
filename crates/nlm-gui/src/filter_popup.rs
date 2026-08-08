//! Per-column value filters, opened from a table header.
//!
//! These filter what is *shown* from data already captured. They are a
//! different mechanism from the CLI's `--vlan`/`--appid`/... flags, which drop
//! frames before they are ever counted. The distinction is deliberate: this
//! front end exists for interactive drill-down into a running or loaded
//! capture, where discarding data early would defeat the point.

use nlm_core::report::DisplayFilter;
use std::collections::{BTreeSet, HashMap};

/// An open header dropdown.
pub struct FilterPopup {
    pub col: usize,
    /// Every value seen in that column, with its current checked state.
    pub choices: Vec<(String, bool)>,
}

impl FilterPopup {
    /// Open the dropdown for `col`, pre-checking whatever is currently shown.
    pub fn open(
        col: usize,
        seen: &HashMap<usize, BTreeSet<String>>,
        filter: &DisplayFilter,
    ) -> FilterPopup {
        let values = seen.get(&col).cloned().unwrap_or_default();
        let allowed = filter.allowed(col);
        let choices = values
            .into_iter()
            .map(|v| {
                // With no filter set, everything is visible and so everything
                // starts checked.
                let on = allowed.is_none_or(|a| a.contains(&v));
                (v, on)
            })
            .collect();
        FilterPopup { col, choices }
    }

    pub fn all_checked(&self) -> bool {
        self.choices.iter().all(|(_, on)| *on)
    }

    pub fn set_all(&mut self, on: bool) {
        for c in &mut self.choices {
            c.1 = on;
        }
    }

    /// The selection to apply, or `None` meaning "no constraint".
    ///
    /// Everything checked collapses to `None` rather than an all-inclusive
    /// set, so the header does not keep advertising a filter that filters
    /// nothing.
    pub fn selection(&self) -> Option<BTreeSet<String>> {
        if self.all_checked() {
            return None;
        }
        Some(self.choices.iter().filter(|(_, on)| *on).map(|(v, _)| v.clone()).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nlm_core::report::COL_VLAN;

    fn seen(values: &[&str]) -> HashMap<usize, BTreeSet<String>> {
        let mut m = HashMap::new();
        m.insert(COL_VLAN, values.iter().map(|s| s.to_string()).collect());
        m
    }

    #[test]
    fn opens_with_everything_checked_when_unfiltered() {
        let p = FilterPopup::open(COL_VLAN, &seen(&["11", "12"]), &DisplayFilter::default());
        assert!(p.all_checked());
        assert_eq!(p.selection(), None);
    }

    #[test]
    fn opens_reflecting_an_existing_filter() {
        let mut f = DisplayFilter::default();
        f.set(COL_VLAN, Some(["11".to_string()].into_iter().collect()));
        let p = FilterPopup::open(COL_VLAN, &seen(&["11", "12"]), &f);
        assert!(!p.all_checked());
        assert_eq!(p.choices, vec![("11".into(), true), ("12".into(), false)]);
    }

    #[test]
    fn a_full_selection_clears_the_filter_instead_of_storing_everything() {
        let mut p = FilterPopup::open(COL_VLAN, &seen(&["11", "12"]), &DisplayFilter::default());
        p.set_all(false);
        assert_eq!(p.selection(), Some(BTreeSet::new()));
        p.set_all(true);
        assert_eq!(p.selection(), None, "all checked must mean unconstrained");
    }

    #[test]
    fn partial_selection_is_carried_through() {
        let mut p = FilterPopup::open(COL_VLAN, &seen(&["11", "12", "13"]), &DisplayFilter::default());
        p.choices[1].1 = false;
        let sel = p.selection().unwrap();
        assert!(sel.contains("11") && sel.contains("13") && !sel.contains("12"));
    }
}
