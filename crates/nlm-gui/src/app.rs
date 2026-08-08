//! The application window.

use crate::filter_popup::FilterPopup;
use egui_extras::{Column, TableBuilder};
use egui_software_backend::SoftwareBackend;
use nlm_core::capture::{select_backend, Capture, StatsSink};
use nlm_core::consts::{LICENSE_NAME, SOFTWARE_NAME, VERSION};
use nlm_core::filter::FrameFilter;
use nlm_core::fmt::{fmt_bytes, fmt_hms};
use nlm_core::iface::{self, Interface};
use nlm_core::pcap::{self, LoadResult};
use nlm_core::report::{
    build_report, DisplayFilter, Report, RowKind, COLUMNS, FILTERABLE_COLUMNS,
};
use nlm_core::stats::{Snapshot, Stats};
use nlm_core::{Protocol, PROTO_ORDER};
use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How long to wait for a stopped backend to drain before the final redraw.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// A capture-file load running on a background thread.
struct LoadJob {
    name: String,
    /// `(packets, bytes, percent)`, written by the loader thread.
    progress: Arc<Mutex<(u64, u64, f64)>>,
    result: Arc<Mutex<Option<Result<LoadResult, String>>>>,
    cancel: Arc<AtomicBool>,
}

pub struct MonitorApp {
    interfaces: Vec<Interface>,
    selected: usize,
    link_mbps: f64,
    duration_s: f64,

    stats: Arc<Stats>,
    capture: Option<Capture>,
    /// Set once Stop is pressed, while the backend is still draining.
    stopping: Option<Instant>,
    started: Option<Instant>,
    last_rotate: Instant,

    snapshot: Option<Snapshot>,
    enabled: BTreeSet<Protocol>,
    display_filter: DisplayFilter,
    seen: HashMap<usize, BTreeSet<String>>,
    open_popup: Option<FilterPopup>,

    load: Option<LoadJob>,
    status: String,
    about_open: bool,
    error: Option<String>,
}

impl MonitorApp {
    pub fn new(ctx: egui::Context) -> MonitorApp {
        ctx.global_style_mut(|s| {
            s.visuals.striped = true;
        });
        MonitorApp::headless()
    }

    /// Construct without a window, so the UI can be exercised in tests.
    fn headless() -> MonitorApp {
        let interfaces = iface::list_interfaces();
        // Prefer a link the OS reports as up with a negotiated speed; that is
        // almost always the one worth watching.
        let selected = interfaces.iter().position(|i| i.speed_mbps.is_some()).unwrap_or(0);
        let link_mbps = interfaces
            .get(selected)
            .and_then(|i| i.speed_mbps)
            .map(f64::from)
            .unwrap_or(100.0);

        MonitorApp {
            interfaces,
            selected,
            link_mbps,
            duration_s: 10.0,
            stats: Arc::new(Stats::new()),
            capture: None,
            stopping: None,
            started: None,
            last_rotate: Instant::now(),
            snapshot: None,
            enabled: BTreeSet::new(),
            display_filter: DisplayFilter::default(),
            seen: HashMap::new(),
            open_popup: None,
            load: None,
            status: "Idle. Pick an interface and press Start, or open a capture file.".into(),
            about_open: false,
            error: None,
        }
    }

    fn is_capturing(&self) -> bool {
        self.capture.is_some()
    }

    fn start(&mut self) {
        let Some(target) = self.interfaces.get(self.selected).cloned() else {
            self.error = Some("No network interface is available to capture on.".into());
            return;
        };
        let backend = match select_backend() {
            Ok(b) => b,
            Err(e) => {
                self.error = Some(e.to_string());
                return;
            }
        };

        // A fresh run starts from zero rather than continuing the last one.
        self.stats = Arc::new(Stats::new());
        self.snapshot = None;
        self.seen.clear();
        // The GUI has no pre-count filters; its column dropdowns filter the
        // display instead, so nothing is discarded before it is counted.
        let sink = StatsSink::new(self.stats.clone(), FrameFilter::default());

        match Capture::start(backend.clone(), &target.id, sink) {
            Ok(c) => {
                self.status = format!("Capturing on {target} via {backend}");
                self.capture = Some(c);
                self.started = Some(Instant::now());
                self.stopping = None;
                self.last_rotate = Instant::now();
            }
            Err(e) => self.error = Some(e.to_string()),
        }
    }

    /// Ask the backend to stop; the final redraw waits for it to drain.
    fn request_stop(&mut self) {
        if let Some(c) = &self.capture {
            c.stop();
            self.stopping = Some(Instant::now());
            self.status = "Stopping...".into();
        }
    }

    fn finish_stop(&mut self) {
        if let Some(mut c) = self.capture.take() {
            c.shutdown();
            if let Some(err) = c.take_error() {
                self.error = Some(err);
            }
        }
        self.stopping = None;
        // Show the whole run, not whatever the final window happened to hold.
        let snap = self.stats.session_snapshot();
        let elapsed = snap.uptime_secs;
        self.status = format!(
            "Stopped. {} packets, {} over {}",
            snap.packets,
            fmt_bytes(snap.bytes as f64),
            fmt_hms(elapsed)
        );
        self.snapshot = Some(snap);
    }

    fn tick_capture(&mut self, ctx: &egui::Context) {
        if !self.is_capturing() {
            return;
        }
        ctx.request_repaint_after(Duration::from_millis(200));

        if let Some(since) = self.stopping {
            let drained = self.capture.as_ref().is_none_or(|c| !c.is_running());
            if drained || since.elapsed() > DRAIN_TIMEOUT {
                self.finish_stop();
            }
            return;
        }

        // Duration of 0 means run until stopped.
        if self.duration_s > 0.0 {
            if let Some(started) = self.started {
                if started.elapsed().as_secs_f64() >= self.duration_s {
                    self.request_stop();
                    return;
                }
            }
        }
        if self.capture.as_ref().is_some_and(|c| !c.is_running()) {
            self.finish_stop();
            return;
        }

        if self.last_rotate.elapsed() >= Duration::from_secs(1) {
            self.stats.rotate();
            self.last_rotate = Instant::now();
        }
        let snap = self.stats.snapshot();
        self.status = format!(
            "Capturing - {} packets, {}, uptime {}",
            snap.packets,
            fmt_bytes(snap.bytes as f64),
            fmt_hms(snap.uptime_secs)
        );
        self.snapshot = Some(snap);
    }

    // ---- capture files --------------------------------------------------

    fn open_capture_file(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            // Only a convenience: what is actually accepted is decided by the
            // file's own magic bytes inside the loader, never its extension.
            .add_filter("Capture files", &["pcap", "pcapng", "cap"])
            .add_filter("All files", &["*"])
            .pick_file()
        else {
            return;
        };
        if self.is_capturing() {
            self.request_stop();
            self.finish_stop();
        }
        self.spawn_load(path);
    }

    fn spawn_load(&mut self, path: PathBuf) {
        let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        let progress = Arc::new(Mutex::new((0u64, 0u64, 0.0f64)));
        let result = Arc::new(Mutex::new(None));
        let cancel = Arc::new(AtomicBool::new(false));

        let job = LoadJob {
            name: name.clone(),
            progress: progress.clone(),
            result: result.clone(),
            cancel: cancel.clone(),
        };

        // A large file takes tens of seconds; loading it on the UI thread
        // would freeze the window for the duration.
        std::thread::spawn(move || {
            let outcome = pcap::load_file(&path, &FrameFilter::default(), &mut |p, b, pct| {
                if let Ok(mut g) = progress.lock() {
                    *g = (p, b, pct);
                }
                !cancel.load(Ordering::Relaxed)
            })
            .map_err(|e| e.to_string());
            if let Ok(mut slot) = result.lock() {
                *slot = Some(outcome);
            }
        });

        self.status = format!("Loading {name}...");
        self.load = Some(job);
    }

    fn poll_load(&mut self, ctx: &egui::Context) {
        let Some(job) = &self.load else {
            return;
        };
        ctx.request_repaint_after(Duration::from_millis(100));

        let finished = job.result.lock().ok().and_then(|mut r| r.take());
        let Some(outcome) = finished else {
            return;
        };
        let name = job.name.clone();
        let cancelled = job.cancel.load(Ordering::Relaxed);
        self.load = None;

        match outcome {
            Ok(res) if !cancelled => {
                self.status = format!(
                    "Loaded {name}: {} packets, {} spanning {:.3} s",
                    res.packets,
                    fmt_bytes(res.bytes as f64),
                    res.duration_s
                );
                self.seen.clear();
                self.stats = Arc::new(Stats::new());
                self.snapshot = Some(Snapshot::offline(
                    res.stats,
                    res.duration_s,
                    res.packets,
                    res.bytes,
                ));
            }
            Ok(_) => self.status = format!("Cancelled loading {name}."),
            Err(e) => {
                self.error = Some(format!("Could not read {name}:\n\n{e}"));
                self.status = format!("Failed to load {name}.");
            }
        }
    }

    // ---- export ---------------------------------------------------------

    /// Export exactly what is on screen, so the file matches what was seen.
    fn export_csv(&mut self, report: &Report) {
        if report.rows.is_empty() {
            self.error = Some("There is nothing to export yet.".into());
            return;
        }
        let default_name = format!("network_monitor_{}.csv", timestamp());
        let Some(path) = rfd::FileDialog::new()
            .set_file_name(default_name)
            .add_filter("CSV", &["csv"])
            .save_file()
        else {
            return;
        };

        let mut out = String::new();
        out.push_str(&COLUMNS.join(","));
        out.push('\n');
        for row in &report.rows {
            let cells: Vec<String> = row.cells.iter().map(|c| csv_escape(c)).collect();
            out.push_str(&cells.join(","));
            out.push('\n');
        }
        match std::fs::write(&path, out) {
            Ok(()) => self.status = format!("Exported {} rows to {}", report.rows.len(), path.display()),
            Err(e) => self.error = Some(format!("Could not write {}:\n\n{e}", path.display())),
        }
    }

    // ---- painting -------------------------------------------------------

    fn toolbar(&mut self, ui: &mut egui::Ui, report: &Report) {
        let busy = self.load.is_some();
        ui.horizontal_wrapped(|ui| {
            ui.label("Interface:");
            let current = self
                .interfaces
                .get(self.selected)
                .map(|i| i.to_string())
                .unwrap_or_else(|| "(none found)".into());
            ui.add_enabled_ui(!self.is_capturing() && !busy, |ui| {
                egui::ComboBox::from_id_salt("iface")
                    .selected_text(current)
                    .width(360.0)
                    .show_ui(ui, |ui| {
                        for (i, iface) in self.interfaces.iter().enumerate() {
                            if ui.selectable_value(&mut self.selected, i, iface.to_string()).clicked() {
                                // Default the load reference to the link's own
                                // negotiated speed when the OS reports one.
                                if let Some(mbps) = iface.speed_mbps {
                                    self.link_mbps = f64::from(mbps);
                                }
                            }
                        }
                    });
            });

            ui.separator();
            ui.label("Link speed:");
            ui.add(
                egui::DragValue::new(&mut self.link_mbps)
                    .range(1.0..=400_000.0)
                    .speed(10.0)
                    .suffix(" Mb/s"),
            );

            ui.separator();
            ui.label("Duration:");
            ui.add(
                egui::DragValue::new(&mut self.duration_s)
                    .range(0.0..=86_400.0)
                    .speed(1.0)
                    .suffix(" s"),
            )
            .on_hover_text("0 runs until stopped. Prefer a long run for MMS/DNP3/IEC104/Modbus, which are bursty.");

            ui.separator();
            ui.add_enabled_ui(!self.is_capturing() && !busy, |ui| {
                if ui.button("\u{25B6} Start").clicked() {
                    self.start();
                }
            });
            ui.add_enabled_ui(self.is_capturing() && self.stopping.is_none(), |ui| {
                if ui.button("\u{25A0} Stop").clicked() {
                    self.request_stop();
                }
            });

            ui.separator();
            if ui.button("Open pcap/pcapng...").clicked() {
                self.open_capture_file();
            }
            if ui.button("Export CSV").clicked() {
                self.export_csv(report);
            }
        });
    }

    fn detail_row(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.label("Detail:");
            for proto in PROTO_ORDER {
                let mut on = self.enabled.contains(&proto);
                // Toggling redraws from the snapshot already in hand, so the
                // table responds immediately rather than at the next tick.
                if ui.checkbox(&mut on, proto.name()).changed() {
                    if on {
                        self.enabled.insert(proto);
                    } else {
                        self.enabled.remove(&proto);
                    }
                }
            }
            ui.separator();
            let active = !self.display_filter.is_empty();
            ui.add_enabled_ui(active, |ui| {
                if ui.button("Clear Filters").clicked() {
                    self.display_filter.clear();
                }
            });
            if active {
                ui.label(egui::RichText::new("column filters active").italics().weak());
            }
        });
    }

    fn table(&mut self, ui: &mut egui::Ui, report: &Report) {
        let text_height = egui::TextStyle::Body.resolve(ui.style()).size + 8.0;
        let mut builder = TableBuilder::new(ui).striped(true).cell_layout(
            egui::Layout::left_to_right(egui::Align::Center),
        );
        for (i, _) in COLUMNS.iter().enumerate() {
            // Protocol and SVID/GOID carry the longest values, so they take
            // the slack; the rest stay at their content width.
            builder = if i == 0 {
                builder.column(Column::auto().at_least(120.0).resizable(true))
            } else if i == 5 {
                builder.column(Column::remainder().at_least(160.0).resizable(true))
            } else {
                builder.column(Column::auto().at_least(60.0).resizable(true))
            };
        }

        let mut clicked_header: Option<usize> = None;
        builder
            .header(text_height + 6.0, |mut header| {
                for (i, name) in COLUMNS.iter().enumerate() {
                    header.col(|ui| {
                        if FILTERABLE_COLUMNS.contains(&i) {
                            let marker = if self.display_filter.is_active(i) { " \u{25BE}" } else { "" };
                            let label = egui::RichText::new(format!("{name}{marker}")).strong();
                            if ui.button(label).clicked() {
                                clicked_header = Some(i);
                            }
                        } else {
                            ui.label(egui::RichText::new(*name).strong());
                        }
                    });
                }
            })
            .body(|body| {
                body.rows(text_height, report.rows.len(), |mut row| {
                    let r = &report.rows[row.index()];
                    for (i, cell) in r.cells.iter().enumerate() {
                        row.col(|ui| {
                            ui.label(style_cell(r, i, cell, ui.visuals()));
                        });
                    }
                });
            });

        if let Some(col) = clicked_header {
            self.open_popup = Some(FilterPopup::open(col, &self.seen, &self.display_filter));
        }
    }

    fn filter_window(&mut self, ctx: &egui::Context) {
        let Some(popup) = &mut self.open_popup else {
            return;
        };
        let col = popup.col;
        let mut close = false;
        let mut apply = false;
        let mut clear = false;

        egui::Window::new(format!("Filter: {}", COLUMNS[col]))
            .collapsible(false)
            .resizable(true)
            .default_width(280.0)
            .show(ctx, |ui| {
                let mut all = popup.all_checked();
                if ui.checkbox(&mut all, "(Select All)").changed() {
                    popup.set_all(all);
                }
                ui.separator();
                egui::ScrollArea::vertical().max_height(320.0).show(ui, |ui| {
                    for (value, on) in &mut popup.choices {
                        ui.checkbox(on, value.as_str());
                    }
                });
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("OK").clicked() {
                        apply = true;
                        close = true;
                    }
                    if ui.button("Clear").clicked() {
                        clear = true;
                        close = true;
                    }
                    if ui.button("Cancel").clicked() {
                        close = true;
                    }
                });
            });

        if apply {
            let selection = self.open_popup.as_ref().and_then(|p| p.selection());
            self.display_filter.set(col, selection);
        }
        if clear {
            self.display_filter.set(col, None);
        }
        if close {
            self.open_popup = None;
        }
    }

    fn dialogs(&mut self, ctx: &egui::Context) {
        if self.about_open {
            let mut open = true;
            egui::Window::new("About")
                .open(&mut open)
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.heading(SOFTWARE_NAME);
                    ui.label(format!("Version {VERSION}"));
                    ui.label(format!("License: {LICENSE_NAME}"));
                    ui.add_space(8.0);
                    ui.label("Captures Ethernet frames and reports throughput and link load per protocol, VLAN and HSR/PRP redundancy lane.");
                });
            self.about_open = open;
        }

        if let Some(msg) = self.error.clone() {
            let mut open = true;
            egui::Window::new("Error")
                .open(&mut open)
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label(msg);
                    ui.add_space(8.0);
                    if ui.button("OK").clicked() {
                        self.error = None;
                    }
                });
            if !open {
                self.error = None;
            }
        }

        if let Some(job) = &self.load {
            let (pkts, bytes, pct) = job.progress.lock().map(|g| *g).unwrap_or((0, 0, 0.0));
            let mut cancel = false;
            egui::Window::new("Loading capture")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label(&job.name);
                    ui.add(egui::ProgressBar::new((pct / 100.0) as f32).show_percentage());
                    ui.label(format!("{pkts} packets ({})", fmt_bytes(bytes as f64)));
                    if ui.button("Cancel").clicked() {
                        cancel = true;
                    }
                });
            if cancel {
                job.cancel.store(true, Ordering::Relaxed);
            }
        }
    }
}

impl egui_software_backend::App for MonitorApp {
    fn ui(&mut self, ui: &mut egui::Ui, _backend: &mut SoftwareBackend) {
        // Panels nest inside the backend's root `Ui`; free-floating windows
        // and repaint scheduling still go through the context.
        let ctx = ui.ctx().clone();
        let ctx = &ctx;

        self.poll_load(ctx);
        self.tick_capture(ctx);

        // Rebuilt every frame so detail toggles and column filters take effect
        // instantly rather than waiting for the next capture tick.
        let report = match &self.snapshot {
            Some(snap) => build_report(snap, &self.enabled, self.link_mbps, &self.display_filter),
            None => build_report(
                &Snapshot::offline(Default::default(), 1.0, 0, 0),
                &self.enabled,
                self.link_mbps,
                &self.display_filter,
            ),
        };
        for (col, values) in &report.seen_values {
            self.seen.entry(*col).or_default().extend(values.iter().cloned());
        }

        egui::Panel::top("menu").show_inside(ui, |ui| {
            egui::MenuBar::new().ui(ui, |ui| {
                ui.menu_button("Help", |ui| {
                    if ui.button("About").clicked() {
                        self.about_open = true;
                        ui.close();
                    }
                });
            });
        });

        egui::Panel::top("toolbar").show_inside(ui, |ui| {
            ui.add_space(4.0);
            self.toolbar(ui, &report);
            ui.add_space(4.0);
            self.detail_row(ui);
            ui.add_space(4.0);
        });

        egui::Panel::bottom("status").show_inside(ui, |ui| {
            ui.add_space(2.0);
            ui.label(&self.status);
            ui.add_space(2.0);
        });

        egui::CentralPanel::default().show_inside(ui, |ui| {
            self.table(ui, &report);
        });

        self.filter_window(ctx);
        self.dialogs(ctx);
    }
}

impl Drop for MonitorApp {
    fn drop(&mut self) {
        // Closing the window must not leave a capture backend running.
        if let Some(c) = &self.capture {
            c.stop();
        }
    }
}

/// Colour a cell by what the row means, not by which column it is in.
fn style_cell(row: &nlm_core::report::Row, col: usize, text: &str, visuals: &egui::Visuals) -> egui::RichText {
    let t = egui::RichText::new(text);
    match row.kind {
        RowKind::Subtotal | RowKind::Idle => t.weak(),
        RowKind::Total => t.strong(),
        _ => {
            // A simulation-flagged frame is not real plant data; make that
            // impossible to miss.
            if col == 8 && row.sim {
                t.color(visuals.error_fg_color).strong()
            } else if col == 10 {
                match row.load_level() {
                    nlm_core::report::LoadLevel::Critical => t.color(visuals.error_fg_color).strong(),
                    nlm_core::report::LoadLevel::Warn => t.color(visuals.warn_fg_color).strong(),
                    nlm_core::report::LoadLevel::Normal => t,
                }
            } else {
                t
            }
        }
    }
}

fn csv_escape(s: &str) -> String {
    if s.contains([',', '"', '\n']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Local timestamp as `YYYYMMDD_HHMMSS`, for default export filenames.
fn timestamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86_400;
    let tod = secs % 86_400;
    let (y, m, d) = civil_from_days(days as i64);
    format!("{y:04}{m:02}{d:02}_{:02}{:02}{:02}", tod / 3600, (tod % 3600) / 60, tod % 60)
}

/// Days since the Unix epoch to a calendar date (Howard Hinnant's algorithm).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nlm_core::parse::parse_frame;

    /// Render the whole window headlessly, the way eframe would each frame.
    ///
    /// This exercises the real widget tree, so a layout rule the table
    /// violates surfaces here rather than as a window that vanishes on the
    /// user's machine.
    fn render(app: &mut MonitorApp) {
        let ctx = egui::Context::default();
        // `run_ui` hands over a root `Ui`, exactly as the software backend
        // does, so panels nest the same way here as they do in the real app.
        let _ = ctx.run_ui(egui::RawInput::default(), |ui| {
            let report = match &app.snapshot {
                Some(snap) => {
                    build_report(snap, &app.enabled, app.link_mbps, &app.display_filter)
                }
                None => build_report(
                    &Snapshot::offline(Default::default(), 1.0, 0, 0),
                    &app.enabled,
                    app.link_mbps,
                    &app.display_filter,
                ),
            };
            egui::Panel::top("toolbar").show_inside(ui, |ui| {
                app.toolbar(ui, &report);
                app.detail_row(ui);
            });
            egui::CentralPanel::default().show_inside(ui, |ui| {
                app.table(ui, &report);
            });
        });
    }

    /// A snapshot holding several protocols, as loading a capture produces.
    fn loaded_snapshot() -> Snapshot {
        let mut stats = nlm_core::stats::StatsMap::new();
        let mut add = |raw: &[u8], bytes: u64| {
            let f = parse_frame(raw);
            let e = stats
                .entry(f.proto)
                .or_default()
                .entry(nlm_core::stats::StatKey::from(&f))
                .or_default();
            e.packets += 1;
            e.bytes += bytes;
        };

        let mut goose = vec![0xFFu8; 12];
        goose.extend_from_slice(&[0x81, 0x00, 0x40, 0x0B, 0x88, 0xB8]);
        goose.extend_from_slice(&[0x40, 0x41, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00]);
        goose.extend_from_slice(&[0x61, 0x05, 0x83, 0x03, b'G', b'O', b'1']);
        add(&goose, 3000);

        let mut goose2 = goose.clone();
        goose2[15] = 0x0C; // a second VLAN, so a subtotal row appears too
        add(&goose2, 2000);

        let mut ptp = vec![0xFFu8; 12];
        ptp.extend_from_slice(&[0x88, 0xF7, 0x00, 0x00]);
        add(&ptp, 500);

        Snapshot::offline(stats, 1.0, 3, 5500)
    }

    #[test]
    fn window_renders_with_an_empty_table() {
        let mut app = MonitorApp::headless();
        render(&mut app);
    }

    /// The crash reported after opening a capture file: an empty window was
    /// fine, a populated one was not.
    #[test]
    fn window_renders_after_a_capture_file_is_loaded() {
        let mut app = MonitorApp::headless();
        app.snapshot = Some(loaded_snapshot());
        app.enabled = PROTO_ORDER.into_iter().collect();
        render(&mut app);
    }

    #[test]
    fn window_renders_with_every_detail_toggle_combination() {
        for proto in PROTO_ORDER {
            let mut app = MonitorApp::headless();
            app.snapshot = Some(loaded_snapshot());
            app.enabled = [proto].into_iter().collect();
            render(&mut app);
        }
    }

    #[test]
    fn window_renders_with_a_column_filter_active() {
        let mut app = MonitorApp::headless();
        app.snapshot = Some(loaded_snapshot());
        app.enabled = PROTO_ORDER.into_iter().collect();
        render(&mut app); // populate `seen`
        app.display_filter
            .set(nlm_core::report::COL_VLAN, Some(["11".to_string()].into_iter().collect()));
        render(&mut app);
    }

    #[test]
    fn csv_quotes_only_what_needs_it() {
        assert_eq!(csv_escape("GOOSE"), "GOOSE");
        assert_eq!(csv_escape("11, 12"), "\"11, 12\"");
        assert_eq!(csv_escape("a\"b"), "\"a\"\"b\"");
    }

    #[test]
    fn civil_dates_match_known_values() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
        // A leap day, which is where naive date maths usually goes wrong.
        assert_eq!(civil_from_days(19_782), (2024, 2, 29));
    }

    #[test]
    fn export_filename_has_the_expected_shape() {
        let t = timestamp();
        assert_eq!(t.len(), 15, "{t}");
        assert_eq!(&t[8..9], "_");
        assert!(t.chars().filter(|c| c.is_ascii_digit()).count() == 14);
    }
}
