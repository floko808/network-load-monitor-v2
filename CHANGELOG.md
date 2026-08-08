# Changelog

## 0.0.1 — first release

Network Load Monitor V2 is a new project, written in Rust and based on the
Python `network_load_monitor` tool that preceded it. It starts its own version
series here rather than continuing the Python one, and succeeds it as the
maintained implementation. The user-facing behaviour, flags and table layout
are carried over deliberately; the changes below are the ones that alter what
you actually see or can do relative to Python 0.0.5.

### Fixed

- **The load percentage was unreadable at substation traffic levels.** The
  column was fixed at two decimals, so a station bus carrying a few tens of
  Kbit/s on a 100 Mb/s link showed `0.00` on every row while their total
  showed `0.01` — a column conveying nothing, and parts that appeared not to
  add up. Precision now scales with the value: `0.001603` where it matters,
  still `20.49` on a busy link, and `<0.0001` rather than a misleading `0.00`
  for traffic too small to quantify.
- **The desktop build could not start in a virtual machine.** It needs no
  graphics driver at all now: the interface is rasterised on the CPU and
  blitted with GDI on Windows, X11/Wayland on Linux. The Windows binaries
  import no OpenGL, Direct3D, Vulkan or C-runtime library — only core Windows
  components — and `build.sh` now asserts that on every build so it cannot
  regress.

  Getting there took three attempts, and the first two were wrong. OpenGL
  failed with "egui_glow requires opengl 2.0+". Direct3D 12 failed with "no
  suitable adapter found", because a Hyper-V guest has no adapter to
  enumerate and egui-wgpu hardcodes `force_fallback_adapter: false`, so it
  cannot ask for a software one. Bundling Mesa's software OpenGL worked around
  the driver problem but cost 59 MB of DLLs beside the executable, which is
  not a portable binary. Rendering in software directly satisfies both
  constraints at once, and cut the desktop binary from 7.8 MB plus 59 MB of
  DLLs to a single 4.7 MB file.
- **Windows binaries would not start.** They imported `VCRUNTIME140.dll` and
  the `api-ms-win-crt-*` stubs, which ship with the Visual C++ Redistributable
  rather than with Windows. On a machine without it the executable failed to
  load — silently, in the case of the desktop build, because a GUI-subsystem
  binary has no console to report to. The C runtime is now linked statically;
  every remaining import is a core Windows component.
- **The desktop build failed silently on any startup error.** `main` returned
  the error, which Rust prints to stderr — which a GUI-subsystem binary does
  not have. Startup failures now open a message box, and an OpenGL-related one
  explains that a graphics driver is missing and that the CLI needs none.
- **Opening a capture file crashed the desktop UI on Linux.** The file dialog
  was built against the XDG portal backend with tokio, but the dialog future
  is driven by `pollster`, so it panicked with "there is no reactor running"
  the moment a dialog opened. This also disabled the panic dialog itself.
- **Link load was measured against a guessed link speed on Windows.** Link
  speed was only ever detected on Linux, by reading `/sys/class/net`. On
  Windows nothing detected it, so every percentage was computed against the
  100 Mb/s default — on a gigabit link, ten times too high, and inconsistent
  with the same capture viewed on Linux. Windows now reads the adapter's
  negotiated speed from the IP Helper API and matches it to the capture
  device by adapter GUID.
- **The terminal front end never detected link speed at all**, on any
  platform; `-s` was the only way to get a meaningful percentage. It now
  defaults to the interface's own negotiated speed and reports which value it
  used and where it came from, so an assumed 100 Mb/s is visible rather than
  silent. `-s` still overrides.
- **Buffered capture backends reported inflated link load.** Rates divided the
  bytes in a window by the wall-clock time that window spanned, but `dumpcap`
  pipes frames in chunks, so several seconds of traffic could land in one
  one-second window and be reported at several times the real load. Rates now
  divide by the longer of the wall-clock window and the stretch of capture
  time the frames themselves cover. This mattered most on Windows, where
  `dumpcap` is the only available backend.
- **Ordinary IP multicast was being counted as R-GOOSE.** Any UDP frame to
  `224.0.0.0/4` was classified as R-GOOSE or R-SV, which swept up mDNS
  (`224.0.0.251`), SSDP (`239.255.255.250`) and IGMP. Classification now
  requires the payload to actually carry a session PDU, with a narrow fallback
  to the reserved `224.0.1.0/24` and `224.0.2.0/24` ranges for session headers
  longer than the scan window. On the reference capture this moved three
  spurious rows out of R-GOOSE and correctly identified a real R-GOOSE stream
  that had been misfiled.
- **R-SV could never be reported.** The address split was documented as
  `224.0.1.x` versus `224.0.2.x` but read the second address octet, which is
  `0` for both, so the R-SV branch was unreachable.
- **Truncated captures now report the load that was on the link.** Statistics
  use each frame's original wire length rather than its captured length, so a
  capture taken with a snaplen no longer under-reports.
- **Non-Ethernet captures are refused** instead of being misparsed into
  plausible-looking nonsense. Loading a Linux cooked-mode or other non-Ethernet
  capture now reports why.
- **The tail of a burst is no longer attributed to the wrong window.** Batched
  frames are flushed when the link goes quiet and when a capture ends, rather
  than waiting for the next burst to push the batch over its threshold.

### Changed

- **Relicensed to `MIT`.** The previous GPL-2.0-only license was
  inherited from `scapy`; there is no longer any packet-capture library
  dependency to inherit from.
- **Offline loading is roughly 100× faster.** A 31 MB pcapng that took 10.8 s
  now loads in 0.10 s, with identical packet and byte counts. A 71 MB capture
  loads in 0.19 s.
- **No runtime to install.** Each front end is a single self-contained
  executable for Linux and Windows; Python, Tk and the library stack are gone.
- **Table layout is computed once.** Both front ends now render from a shared
  row builder instead of each deriving rows separately.
- **`.pcapng` is read natively**, along with classic pcap in both byte orders
  and both timestamp resolutions.
- **The desktop UI moved from Tkinter to egui**, which is what makes a single
  dependency-free binary possible on both platforms.
- **Interface listing reports link speed** where the OS provides it, and the
  desktop UI defaults its load reference to the selected link's negotiated
  speed.
- **Filter values are validated before a capture starts**, so a typo fails
  immediately rather than silently matching nothing.

### Added

- A test suite: 83 tests covering the classifier against hand-built frames,
  malformed and truncated input at every length, capture-file parsing, the
  statistics model, report construction and terminal rendering. The Python
  version had no automated tests.
- Cancellation for in-progress capture-file loads in the desktop UI.
- `build.sh`, which tests, cross-builds both platforms, smoke-tests the
  results and writes `SHA256SUMS`.

### Notes

- `sim` is now reported as unknown rather than as a value when the goosePdu
  tag check fails, since the flag comes from a header that turned out not to
  precede a goosePdu.
- Capture-file magic-byte validation is retained from the original, including
  its rejection of gzip-wrapped files as a decompression-bomb guard.

---

## 0.0.5 and earlier — Python implementation

See the changelog in the original `network_load_monitor` repository.
