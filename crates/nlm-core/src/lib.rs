//! Capture engine, frame classifier and statistics model for
//! Network Load Monitor V2.
//!
//! Both front ends — the terminal UI and the desktop UI — are thin consumers
//! of this crate. Classification, filtering, the rolling-window statistics and
//! the table layout all live here exactly once, so the two cannot disagree
//! about what a capture means.
//!
//! ```no_run
//! use nlm_core::{parse::parse_frame, stats::Stats};
//!
//! let stats = Stats::new();
//! let frame = parse_frame(&[0u8; 64]);
//! stats.record(&frame, 64);
//! stats.rotate();
//! ```

pub mod capture;
pub mod consts;
pub mod filter;
pub mod fmt;
pub mod iface;
pub mod parse;
pub mod pcap;
pub mod report;
pub mod stats;

pub use consts::{LICENSE_NAME, SOFTWARE_NAME, VERSION};
pub use parse::{parse_frame, Frame, Protocol, PROTO_ORDER};
