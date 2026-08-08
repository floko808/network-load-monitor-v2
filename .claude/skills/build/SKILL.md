---
name: build
description: Build, test, cross-compile and package Network Load Monitor V2. Use when asked to build, compile, test, cross-compile for Windows, produce release binaries, check the dist/ artifacts, or run either front end. Covers ./build.sh, cargo-xwin, the portability gate, and the constraints a change must not break.
---

# Building Network Load Monitor V2

A Cargo workspace producing four self-contained executables: a terminal front
end and a CPU-rendered desktop front end, for Linux and for Windows.

```
crates/nlm-core   engine: parsing, filtering, capture, stats, report (a lib)
crates/nlm-cli    binary: network-monitor       (console)
crates/nlm-gui    binary: network-monitor-gui   (GUI subsystem, no console)
```

Everything goes through `build.sh` at the repo root. Prefer it over bare
`cargo build` for anything that produces a deliverable — it also runs the
tests, the portability gate, the smoke tests and the checksums.

## Commands

```bash
./build.sh            # test, then build Linux + Windows into dist/
./build.sh linux      # tests + Linux build + smoke test + checksums
./build.sh windows    # tests + Windows cross-build + portability gate + checksums
./build.sh test       # cargo test --workspace, nothing else
```

Fast inner loop while editing (no packaging, no cross-build):

```bash
cargo test --workspace                # ~83 tests, the real gate on the engine
cargo clippy --workspace --all-targets
cargo build --workspace               # debug
cargo run -p nlm-cli -- --list        # list interfaces
cargo run -p nlm-cli -- --pcap FILE --all
cargo run -p nlm-gui                  # desktop front end
```

The GUI needs a display. Under an agent/headless session, run it with a
timeout and treat exit code 124 as success — it means the window stayed up:

```bash
timeout 10 ./target/debug/network-monitor-gui; echo "exit=$? (124 = still running)"
```

## Prerequisites

- Rust 1.82 or newer (`rust-version` in the workspace manifest).
- For the Windows target, `cargo-xwin` — no root, no distro packages:

```bash
cargo install cargo-xwin
rustup target add x86_64-pc-windows-msvc
```

  First use downloads the Microsoft CRT and Windows SDK import libraries into
  the cargo cache; later builds are offline. MSVC is chosen over
  `x86_64-pc-windows-gnu` because it needs no system-wide mingw and because
  `rfd` links the Windows SDK directly.
- Optional: `objdump` (skips the portability gate if absent — it warns rather
  than failing, so a machine without binutils can silently lose the check) and
  `wine` (skips executing the `.exe`s if absent).

## What a build verifies

`build.sh windows` fails the build if either `.exe` imports `opengl32`,
`d3d11`, `d3d12`, `dxgi`, `vulkan`, `VCRUNTIME*`, `MSVCP*` or the
`api-ms-win-crt-*` stubs. That is the single most important gate in the repo:
the promise is one file copied to a substation laptop or a Hyper-V guest with
no graphics driver and no Visual C++ Redistributable. The static CRT comes
from `.cargo/config.toml` (`-C target-feature=+crt-static`); the absence of a
graphics dependency comes from `egui_software_backend` rasterising on the CPU.

Then it smoke-tests: `--version` and `--list` on the Linux CLI, and the
Windows CLI under `wine` when available. Finally it writes `dist/SHA256SUMS`
so a copy can be verified after transfer.

## Artifacts

```
dist/linux/network-monitor          dist/windows/network-monitor.exe
dist/linux/network-monitor-gui      dist/windows/network-monitor-gui.exe
dist/LICENSE-MIT                    dist/LICENSE-APACHE
dist/THIRD-PARTY-LICENSES.md        dist/SHA256SUMS
```

`copy_legal` places the three license files and fails the build if any is
missing — `dist/` is a redistributable drop, not just binaries, and shipping it
without them would be a license violation. Regenerate
`THIRD-PARTY-LICENSES.md` (the commands are at the bottom of that file) after
any dependency change.

`dist/` and `target/` are gitignored. Check the subsystems are right after a
Windows build — `file dist/windows/*.exe` should show the CLI as a console
PE32+ and the GUI as a GUI-subsystem PE32+, or the desktop binary opens a
stray console window.

Release profile (workspace root): `opt-level = 3`, `lto = "thin"`,
`codegen-units = 1`, `strip = true`, `panic = "abort"`. Because panics abort
and the GUI has no stderr, the GUI installs its own panic hook and reports
through a message box — do not remove it while `panic = "abort"` stands.

## Constraints a change must not break

- **No GPU dependency in `nlm-gui`.** Pulling in `eframe`, `wgpu`, `glow` or
  any windowing crate with a graphics backend fails the portability gate. The
  alternative considered and rejected was shipping software OpenGL: 59 MB of
  DLLs beside the executable, which is no longer a portable binary.
- **`rfd` stays on `xdg-portal` + `async-std`.** It is pinned with
  `default-features = false`. `rfd` drives its dialog future with `pollster`,
  so a tokio-backed zbus panics with "there is no reactor running" the moment
  a dialog opens — including the panic message box itself.
- **No packet-capture library.** The classifier, both capture-file readers and
  the raw-socket backend are written directly. This is what keeps the license
  `MIT` instead of inheriting GPL from `scapy`/libpcap. `dumpcap` is *executed*
  as a subprocess, never linked.
- **Table logic lives once**, in `nlm-core::report::build_report`. Both front
  ends consume it; neither recomputes rows.

## Running what you built

Reading a `.pcap`/`.pcapng` needs no privileges on either platform. Live
capture does:

- **Linux** — `sudo`, or `sudo setcap cap_net_raw+eip ./network-monitor`, or
  join the `wireshark` group (the tool falls back to `dumpcap` automatically
  when it cannot open an `AF_PACKET` socket).
- **Windows** — Wireshark/Npcap must be installed, and either run elevated or
  uncheck Npcap's "Restrict Npcap driver's access to Administrators only".

A capture file carries no link speed, so `--pcap` assumes 100 Mb/s unless `-s`
says otherwise; percentages are meaningless if that is wrong.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `cargo-xwin not found` | `cargo install cargo-xwin` |
| `Rust target missing` | `rustup target add x86_64-pc-windows-msvc` |
| First Windows build hangs on network | cargo-xwin fetching the CRT/SDK; one-off |
| `Windows binaries are not self-contained` | A new dependency pulled in a graphics or CRT import — check the listed DLLs, not the crate name |
| `objdump not found; skipping portability check` | Install binutils; the gate is silently off until you do |
| GUI panics on opening a file dialog | An async runtime other than async-std reached `rfd`/zbus |
| GUI exits immediately under an agent session | No display; expected — use the `timeout` form above |

For end-to-end validation beyond the unit tests, run real captures through
`--pcap` and compare packet and byte totals against Wireshark. On the
reference captures they agree exactly (46,263 packets / 28.4 MB from a 31 MB
pcapng).

## Related

`SKILL.md` at the repo root is the full from-scratch recreation spec — every
byte-level parsing rule, the CLI/GUI behaviour, the suggested build order.
Read that when *writing* the code; read this one when *building* it.
