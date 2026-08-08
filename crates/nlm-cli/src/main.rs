//! Terminal front end.

mod table;

use clap::Parser;
use crossterm::{cursor, execute, terminal};
use nlm_core::capture::{select_backend, Capture, StatsSink};
use nlm_core::filter::{self, FrameFilter};
use nlm_core::fmt::fmt_bytes;
use nlm_core::iface;
use nlm_core::pcap;
use nlm_core::report::{build_report, DisplayFilter};
use nlm_core::stats::{Snapshot, Stats};
use nlm_core::{Protocol, PROTO_ORDER};
use std::collections::BTreeSet;
use std::error::Error;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

// clap prints this as "<bin name> <long_version>", so the version leads.
const LONG_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "\nNetwork Load Monitor V2",
    "\nLicense: MIT"
);

const EPILOG: &str = "\
PROTOCOL IDENTIFICATION
  GOOSE              EtherType 0x88B8
  Sampled Values     EtherType 0x88BA
  R-GOOSE            UDP multicast (IEC 61850-8-2)
  PTP / IEEE 1588    EtherType 0x88F7
  MMS                TCP port 102   + TPKT header check (unicast)
  DNP3               TCP/UDP 20000  + data-link sync bytes (unicast)
  IEC104             TCP port 2404  + APCI start byte (unicast)
  Modbus TCP         TCP port 502   + MBAP header check (unicast)

  For the four unicast protocols the well-known port is only a hint. A frame
  on a matching port whose payload does not parse as that protocol's framing
  stays classified as IPv4 (and folds into \"Other\") rather than being
  mislabelled by port number alone.

  Everything else -- R-SV, GSSE, NTP, LLDP, RSTP, ARP, IPv4, IPv6 and any
  unclassified traffic -- is recognised internally but always aggregated into
  the single \"Other\" row.

  HSR/PRP redundancy (in-frame tag 0x892F, RCT trailer 0x88FB) and VLAN/QinQ
  tagging are detected and reported regardless of which protocol flags are set.

BURSTY PROTOCOLS
  MMS, DNP3, IEC104 and Modbus TCP are unicast and often bursty rather than
  continuous: a client polling by report-by-exception may exchange a handful
  of packets every 10-60 s and nothing in between. A short capture can start
  and stop without ever landing on a burst -- that is a quiet capture window,
  not a detection failure. Use a longer --duration (or 0 to run until stopped)
  so the capture spans at least one full cycle. Once seen, a protocol's rows
  stay on screen between bursts, marked \"idle Ns\".

TABLE COLUMNS
  Protocol, VLAN (802.1Q/QinQ id), CoS (802.1Q PCP), Redundancy (HSR-A/B or
  PRP-A/B), AppID, SVID/GOID, noASDU/stNum, confRev, Sim (simulation flag),
  bits/s, and % of the configured link speed. A \"Sum <protocol>\" row appears
  when a protocol spans several VLAN/redundancy combinations; TOTAL is the
  grand sum. When the capture ends, the table is redrawn once as a session
  total covering the whole run, not just the final window.

FILTERS
  Filter flags drop frames before they are counted at all -- they never appear
  in the table, the totals or the session summary. Comma-separated values
  within one flag are OR'd; different flags are AND'd together. --goid and
  --svid both filter the shared SVID/GOID column and are OR'd if both given.
  --vlan matches any tag in a stacked (QinQ) frame, not just the outermost.

CAPTURE BACKENDS
  A raw AF_PACKET socket is used when the process has CAP_NET_RAW (via sudo,
  or setcap cap_net_raw+eip on this binary). Otherwise it falls back to
  Wireshark's dumpcap helper, which works unprivileged for members of the
  wireshark group on Linux, or on Windows once Npcap's admin-only restriction
  is lifted.

EXAMPLES
  network-monitor                            eth0, 10 s, 100 Mb/s
  network-monitor eth0 -d 30                 capture for 30 seconds
  network-monitor eth1 -s 1000 -d 0          1 Gb/s link, run until stopped
  network-monitor eth0 -r 2 -d 60            2 s statistics window
  network-monitor --list                     show available interfaces
  network-monitor eth0 --goose --sv          break out GOOSE and SV detail
  network-monitor eth0 --all                 break out every supported protocol
  network-monitor eth0 --vlan 11 --appid 0x4041
  network-monitor eth0 --redundancy prp      only PRP traffic, either lane
  network-monitor --pcap capture.pcapng --goose --ptp
";

#[derive(Parser, Debug)]
#[command(
    name = "network-monitor",
    version,
    long_version = LONG_VERSION,
    about = "Capture Ethernet frames and report per-protocol throughput and link load",
    after_long_help = EPILOG,
)]
struct Args {
    /// Network interface to capture on
    #[arg(default_value = "eth0")]
    interface: String,

    /// Stop after this many seconds; 0 = run until stopped
    #[arg(short, long, value_name = "SEC", default_value_t = 10.0)]
    duration: f64,

    /// Link speed in Mb/s used for the load percentage
    /// [default: the interface's own negotiated speed, else 100]
    #[arg(short, long, value_name = "MBPS")]
    speed: Option<f64>,

    /// Statistics window / display refresh in seconds
    #[arg(short, long, value_name = "SEC", default_value_t = 1.0)]
    refresh: f64,

    /// List available network interfaces and exit
    #[arg(short, long)]
    list: bool,

    /// Read a .pcap/.pcapng file and print a static summary instead of capturing
    #[arg(long, value_name = "FILE")]
    pcap: Option<PathBuf>,

    /// Show detailed GOOSE breakdown
    #[arg(long, help_heading = "Protocol detail")]
    goose: bool,
    /// Show detailed Sampled Values breakdown
    #[arg(long, help_heading = "Protocol detail")]
    sv: bool,
    /// Show detailed R-GOOSE breakdown
    #[arg(long, help_heading = "Protocol detail")]
    rgoose: bool,
    /// Show detailed PTP breakdown
    #[arg(long, help_heading = "Protocol detail")]
    ptp: bool,
    /// Show detailed MMS breakdown (TCP port 102)
    #[arg(long, help_heading = "Protocol detail")]
    mms: bool,
    /// Show detailed DNP3 breakdown (TCP/UDP port 20000)
    #[arg(long, help_heading = "Protocol detail")]
    dnp3: bool,
    /// Show detailed IEC104 breakdown (TCP port 2404)
    #[arg(long, help_heading = "Protocol detail")]
    iec104: bool,
    /// Show detailed Modbus TCP breakdown (TCP port 502)
    #[arg(long, help_heading = "Protocol detail")]
    modbus: bool,
    /// Show detailed breakdown for every supported protocol
    #[arg(long, help_heading = "Protocol detail")]
    all: bool,

    /// Only include frames tagged with one of these VLAN IDs
    #[arg(long, value_name = "ID[,ID...]", help_heading = "Filters")]
    vlan: Option<String>,
    /// Only include frames matching hsr/prp/none, or a lane (hsr-a/hsr-b/prp-a/prp-b)
    #[arg(long, value_name = "VALUE[,VALUE...]", help_heading = "Filters")]
    redundancy: Option<String>,
    /// Only include frames with this AppID (hex)
    #[arg(long, value_name = "HEX[,HEX...]", help_heading = "Filters")]
    appid: Option<String>,
    /// Only include frames with this GOOSE ID (goID/gocbRef)
    #[arg(long, value_name = "ID[,ID...]", help_heading = "Filters")]
    goid: Option<String>,
    /// Only include Sampled Values frames with this SVID
    #[arg(long, value_name = "ID[,ID...]", help_heading = "Filters")]
    svid: Option<String>,
}

impl Args {
    fn enabled_protocols(&self) -> BTreeSet<Protocol> {
        if self.all {
            return PROTO_ORDER.into_iter().collect();
        }
        let picked = [
            (self.goose, Protocol::Goose),
            (self.sv, Protocol::SampledValues),
            (self.rgoose, Protocol::RGoose),
            (self.ptp, Protocol::Ptp),
            (self.mms, Protocol::Mms),
            (self.dnp3, Protocol::Dnp3),
            (self.iec104, Protocol::Iec104),
            (self.modbus, Protocol::ModbusTcp),
        ];
        picked.into_iter().filter(|(on, _)| *on).map(|(_, p)| p).collect()
    }

    fn frame_filter(&self) -> Result<FrameFilter, String> {
        // --goid and --svid target the same column, so they merge into one set.
        let mut svids: Option<BTreeSet<String>> = None;
        for s in [&self.goid, &self.svid].into_iter().flatten() {
            svids.get_or_insert_with(BTreeSet::new).extend(filter::parse_ids(s));
        }
        Ok(FrameFilter {
            vlans: self.vlan.as_deref().map(filter::parse_vlans).transpose()?,
            redundancy: self.redundancy.as_deref().map(filter::parse_redundancy).transpose()?,
            appids: self.appid.as_deref().map(filter::parse_appids).transpose()?,
            svids,
        })
    }
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let _ = restore_terminal();
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &Args) -> Result<(), Box<dyn Error>> {
    if args.list {
        return list_interfaces();
    }
    let enabled = args.enabled_protocols();
    let frame_filter = args.frame_filter()?;

    if let Some(path) = &args.pcap {
        return run_offline(path, args, &enabled, &frame_filter);
    }
    run_live(args, &enabled, &frame_filter)
}

fn list_interfaces() -> Result<(), Box<dyn Error>> {
    let list = iface::list_interfaces();
    if list.is_empty() {
        eprintln!("no network interfaces found");
        return Ok(());
    }
    println!("Available interfaces:");
    for i in &list {
        match i.speed_mbps {
            Some(mbps) => println!("  {i}  [{mbps} Mb/s]"),
            None => println!("  {i}"),
        }
    }
    Ok(())
}

// =========================================================================
// Offline
// =========================================================================

fn run_offline(
    path: &Path,
    args: &Args,
    enabled: &BTreeSet<Protocol>,
    frame_filter: &FrameFilter,
) -> Result<(), Box<dyn Error>> {
    let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let show_progress = io::stderr().is_terminal();
    let mut last_drawn = Instant::now() - Duration::from_secs(1);

    // A capture file carries no link speed, so only an explicit flag can
    // set the reference here.
    let speed = args.speed.unwrap_or(nlm_core::consts::DEFAULT_LINK_MBPS);
    let result = pcap::load_file(path, frame_filter, &mut |pkts, bytes, pct| {
        // Redrawing on every callback would dominate the load itself on a
        // large file; a few updates a second is plenty for a human.
        if show_progress && last_drawn.elapsed() >= Duration::from_millis(100) {
            last_drawn = Instant::now();
            draw_progress(&name, pkts, bytes, pct);
        }
        true
    })?;
    if show_progress {
        draw_progress(&name, result.packets, result.bytes, 100.0);
        eprintln!();
    }

    let snap = Snapshot::offline(result.stats, result.duration_s, result.packets, result.bytes);
    let report = build_report(&snap, enabled, speed, &DisplayFilter::default());
    let context = format!("{name} @ {speed} Mb/s");
    let extra = filter_note(frame_filter);

    let width = terminal::size().map(|(w, _)| w as usize).unwrap_or(120);
    for line in table::render(&report, &context, &extra, width) {
        println!("{line}");
    }
    Ok(())
}

fn draw_progress(name: &str, pkts: u64, bytes: u64, pct: f64) {
    const WIDTH: usize = 30;
    let filled = ((pct / 100.0) * WIDTH as f64).round() as usize;
    eprint!(
        "\rLoading {name} [{}{}] {pct:5.1}%  {pkts} packets ({})   ",
        "#".repeat(filled.min(WIDTH)),
        ".".repeat(WIDTH - filled.min(WIDTH)),
        fmt_bytes(bytes as f64)
    );
    let _ = io::stderr().flush();
}

// =========================================================================
// Live capture
// =========================================================================

fn run_live(
    args: &Args,
    enabled: &BTreeSet<Protocol>,
    frame_filter: &FrameFilter,
) -> Result<(), Box<dyn Error>> {
    let interfaces = iface::list_interfaces();
    let target = match iface::resolve(&args.interface, &interfaces) {
        Some(i) => i.clone(),
        None => {
            let mut msg = format!("no such interface: {}\n\nAvailable interfaces:", args.interface);
            for i in &interfaces {
                msg.push_str(&format!("\n  {i}"));
            }
            return Err(msg.into());
        }
    };

    // Measure load against the link's own negotiated speed unless told
    // otherwise. Assuming 100 Mb/s on a gigabit link silently reports every
    // percentage ten times too high, which is worse than useless on a tool
    // whose entire job is reporting link load.
    let (speed, speed_origin) = match args.speed {
        Some(s) => (s, "as given"),
        None => match target.speed_mbps {
            Some(mbps) => (f64::from(mbps), "detected"),
            None => (nlm_core::consts::DEFAULT_LINK_MBPS, "assumed; set -s for this link"),
        },
    };

    let backend = select_backend()?;
    let stats = Arc::new(Stats::new());
    let sink = StatsSink::new(stats.clone(), frame_filter.clone());

    eprintln!(
        "Starting capture on {} at {} Mb/s ({}), {:.1}s window, {}, via {}",
        target,
        speed,
        speed_origin,
        args.refresh,
        if args.duration > 0.0 {
            format!("{:.0}s duration", args.duration)
        } else {
            "running until stopped".to_string()
        },
        backend
    );

    let mut capture = Capture::start(backend, &target.id, sink)?;

    let interrupted = Arc::new(AtomicBool::new(false));
    {
        let flag = interrupted.clone();
        // Ignore a failure to install the handler: Ctrl-C then terminates the
        // process outright, which is a worse experience but not a reason to
        // refuse to capture at all.
        let _ = ctrlc::set_handler(move || flag.store(true, Ordering::Relaxed));
    }

    let context = format!("{} @ {speed} Mb/s", target.id);
    let extra = filter_note(frame_filter);
    let refresh = args.refresh.max(0.05);
    let redraw_period = Duration::from_secs_f64((1.0 / (2.0f64).max(2.0 / refresh)).min(0.5));

    let live = io::stdout().is_terminal();
    if live {
        let mut out = io::stdout();
        let _ = execute!(out, terminal::Clear(terminal::ClearType::All), cursor::Hide);
    }

    let started = Instant::now();
    let mut last_rotate = Instant::now();
    loop {
        if interrupted.load(Ordering::Relaxed) || !capture.is_running() {
            break;
        }
        if args.duration > 0.0 && started.elapsed().as_secs_f64() >= args.duration {
            break;
        }
        if last_rotate.elapsed().as_secs_f64() >= refresh {
            stats.rotate();
            last_rotate = Instant::now();
        }
        if live {
            draw(&stats.snapshot(), enabled, speed, &context, &extra)?;
        }
        std::thread::sleep(redraw_period);
    }

    capture.stop();
    // dumpcap buffers, so frames captured moments ago may still be in flight
    // through the pipe. Redrawing immediately would under-report that tail.
    let drain_deadline = Instant::now() + Duration::from_secs(5);
    while capture.is_running() && Instant::now() < drain_deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    capture.shutdown();

    // The final view is the whole run, not whatever the last window held.
    draw(&stats.session_snapshot(), enabled, speed, &context, &extra)?;
    restore_terminal()?;

    if let Some(err) = capture.take_error() {
        return Err(err.into());
    }
    Ok(())
}

fn draw(
    snap: &Snapshot,
    enabled: &BTreeSet<Protocol>,
    speed: f64,
    context: &str,
    extra: &str,
) -> Result<(), Box<dyn Error>> {
    let report = build_report(snap, enabled, speed, &DisplayFilter::default());
    let width = terminal::size().map(|(w, _)| w as usize).unwrap_or(120);
    let lines = table::render(&report, context, extra, width);

    let mut out = io::stdout();
    if io::stdout().is_terminal() {
        execute!(out, cursor::MoveTo(0, 0))?;
        for line in &lines {
            write!(out, "{line}")?;
            execute!(out, terminal::Clear(terminal::ClearType::UntilNewLine))?;
            writeln!(out)?;
        }
        execute!(out, terminal::Clear(terminal::ClearType::FromCursorDown))?;
    } else {
        for line in &lines {
            writeln!(out, "{line}")?;
        }
    }
    out.flush()?;
    Ok(())
}

fn restore_terminal() -> Result<(), Box<dyn Error>> {
    if io::stdout().is_terminal() {
        execute!(io::stdout(), cursor::Show)?;
    }
    Ok(())
}

fn filter_note(f: &FrameFilter) -> String {
    if f.is_empty() {
        String::new()
    } else {
        format!("filter {}", f.summary())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse(argv: &[&str]) -> Args {
        Args::parse_from(std::iter::once("network-monitor").chain(argv.iter().copied()))
    }

    #[test]
    fn cli_definition_is_valid() {
        Args::command().debug_assert();
    }

    #[test]
    fn defaults_match_the_documented_behaviour() {
        let a = parse(&[]);
        assert_eq!(a.interface, "eth0");
        assert_eq!(a.duration, 10.0);
        assert_eq!(a.speed, None); // resolved from the interface at run time
        assert_eq!(a.refresh, 1.0);
        // Every protocol folds into "Other" until asked for explicitly.
        assert!(a.enabled_protocols().is_empty());
    }

    #[test]
    fn all_is_the_union_of_the_individual_detail_flags() {
        assert_eq!(parse(&["--all"]).enabled_protocols(), PROTO_ORDER.into_iter().collect());
        let each = parse(&[
            "--goose", "--sv", "--rgoose", "--ptp", "--mms", "--dnp3", "--iec104", "--modbus",
        ]);
        assert_eq!(each.enabled_protocols(), parse(&["--all"]).enabled_protocols());
    }

    #[test]
    fn individual_flags_select_only_themselves() {
        let a = parse(&["--goose", "--sv"]);
        let got = a.enabled_protocols();
        assert!(got.contains(&Protocol::Goose) && got.contains(&Protocol::SampledValues));
        assert!(!got.contains(&Protocol::Ptp));
    }

    #[test]
    fn goid_and_svid_merge_into_one_id_filter() {
        let f = parse(&["--goid", "gooseA", "--svid", "svB"]).frame_filter().unwrap();
        let ids = f.svids.unwrap();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains("GOOSEA") && ids.contains("SVB"));
    }

    #[test]
    fn filter_flags_are_validated_before_capturing() {
        assert!(parse(&["--redundancy", "hsr-c"]).frame_filter().is_err());
        assert!(parse(&["--vlan", "9999"]).frame_filter().is_err());
        assert!(parse(&["--appid", "nothex"]).frame_filter().is_err());
        assert!(parse(&["--redundancy", "prp-b"]).frame_filter().is_ok());
    }

    #[test]
    fn no_filter_flags_means_no_filtering() {
        assert!(parse(&[]).frame_filter().unwrap().is_empty());
        assert!(filter_note(&parse(&[]).frame_filter().unwrap()).is_empty());
        let f = parse(&["--vlan", "11"]).frame_filter().unwrap();
        assert!(filter_note(&f).starts_with("filter "));
    }
}
