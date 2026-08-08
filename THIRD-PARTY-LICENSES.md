# Third-party licenses

Network Load Monitor V2 is licensed [MIT](LICENSE-MIT). This file lists every
third-party crate linked into the shipped binaries, so that a copy of
`network-monitor` or `network-monitor-gui` can be redistributed with correct
attribution.

**Why there is still an `LICENSE-APACHE` file next to an MIT project.** Some
dependencies are Apache-2.0 licensed, and Apache-2.0 §4(a) requires that a copy
of the license reach every recipient of a work that contains such code. That
file is therefore a *third-party notice*, not an alternative license for this
project's code — there is no "or Apache-2.0, at your option" here. Do not
delete it from a distribution.

## Summary

**Every dependency is under a permissive license, and none of them constrains
the license of this project.** There is no copyleft anywhere in the dependency
graph: no GPL, LGPL, MPL, EPL or CDDL component is linked, and no dependency
requires derived works to be released under its own terms.

That is a deliberate property, not a coincidence. All protocol parsing, both
capture-file readers and the raw-socket backend are implemented directly in
this project, so no packet-capture library is linked and no license is
inherited from one. `dumpcap` is *executed* as a separate process when the
raw-socket backend is unavailable, never linked, so its GPL terms do not
reach this code. This is what allowed the relicense away from the GPL-2.0-only
Python implementation, which inherited its terms from `scapy`.

Two clarifications on what "match our license" means in practice, because they
are not quite the same thing:

- **Compatibility** — satisfied in full. Everything here can be combined with
  MIT-licensed code and shipped in a closed or open binary. MIT is the more
  permissive license, so nothing in this graph conflicts with it.
- **Identity** — not literally true of every crate, and it does not need to be.
  Roughly 200 of the 239 crates offer `MIT OR Apache-2.0` (or a spelling
  variant), and for those this project simply takes the MIT option. The
  remainder are permissive under slightly different terms — Apache-2.0,
  BSD-2-Clause, BSD-3-Clause, ISC, Zlib, Unicode-3.0, OFL-1.1 — all of which
  are attribution-only licenses. What they require is that their notices travel
  with the binary, which is the purpose of this file.

Note that being MIT does **not** let a distributor ignore the Apache-2.0
components: MIT governs this project's own source, while each dependency is
still governed by its own terms in the compiled result.

### The dependencies worth knowing about individually

| Crate | License | Why it is called out |
|---|---|---|
| `winit` | Apache-2.0 **only** | Not dual-licensed, and the reason `LICENSE-APACHE` ships with an MIT project. Its Apache-2.0 terms — attribution, NOTICE propagation, the patent grant — apply to the distributed binary regardless of this project being MIT. Windowing for the desktop front end; both platforms. |
| `dpi` | Apache-2.0 **AND** MIT | Conjunctive, not a choice: both sets of terms apply. Pulled in by `winit`. |
| `self_cell` | Apache-2.0 OR GPL-2.0-only | The only mention of the GPL in the graph, and it is a *choice*. This project takes the Apache-2.0 option, so no GPL obligation attaches. Reached through `epaint`, so it is in both builds. |
| `epaint_default_fonts` | (MIT OR Apache-2.0) AND OFL-1.1 AND Ubuntu-font-1.0 | Embedded font data. The SIL Open Font License and the Ubuntu Font Licence are conjunctive with the code license and apply to the font glyphs compiled into the desktop binary. Neither is copyleft over the program: OFL-1.1 restricts selling the *fonts* on their own and reserves font names, which shipping them inside an application does not trigger. |
| `tiny-skia`, `tiny-skia-path` | BSD-3-Clause | Attribution plus a no-endorsement clause. Linux only — client-side window decorations under Wayland. |
| `arrayref` | BSD-2-Clause | Attribution only. Linux only. |
| `libloading` | ISC | Attribution only. Linux only. |
| `foldhash` | Zlib | Attribution only, and it does not require notices for binary distribution at all. |
| `ab_glyph`, `ab_glyph_rasterizer`, `owned_ttf_parser`, `gethostname` | Apache-2.0 only | Same reasoning as `winit`, on a smaller scale. Linux only. |
| ICU crates (`icu_*`, `zerovec`, `yoke`, `tinystr`, …) | Unicode-3.0 | Permissive, OSI-approved, attribution only. Linux only — reached through `url`/`idna` under the XDG portal file dialog. |

Note that the Windows build has the shorter graph of the two: 98 crates against
229 on Linux. The Wayland/X11 stack, the XDG portal dialog and its ICU
transitive dependencies are all Linux-only, so every BSD-, ISC- and
Unicode-licensed component above is absent from the `.exe` files.

## Complying when you redistribute

For a binary-only distribution of either executable, ship this file alongside
it, together with `LICENSE-MIT` (this project's license) and `LICENSE-APACHE`
(required by the Apache-2.0 dependencies). That satisfies the attribution
requirement of every license listed here. If you redistribute the Windows build
only, the crates marked "Linux" below do not apply.

`./build.sh` copies all three into `dist/` for exactly this reason, so copying
that directory as a whole is already compliant — there is no separate step to
remember.

## Full dependency list

Direct and transitive runtime dependencies of the shipped binaries, as resolved
by `Cargo.lock`. Build-time-only and test-only dependencies are excluded.
"Platform" is the target whose binary links the crate.

| Crate | Version | License | Platform |
|---|---|---|---|
| `ab_glyph` | 0.2.32 | Apache-2.0 | Linux |
| `ab_glyph_rasterizer` | 0.1.10 | Apache-2.0 | Linux |
| `accesskit` | 0.24.1 | MIT OR Apache-2.0 | Both |
| `ahash` | 0.8.12 | MIT OR Apache-2.0 | Both |
| `anstream` | 1.0.0 | MIT OR Apache-2.0 | Both |
| `anstyle` | 1.0.14 | MIT OR Apache-2.0 | Both |
| `anstyle-parse` | 1.0.0 | MIT OR Apache-2.0 | Both |
| `anstyle-query` | 1.1.5 | MIT OR Apache-2.0 | Both |
| `anstyle-wincon` | 3.0.11 | MIT OR Apache-2.0 | Windows |
| `arrayref` | 0.3.9 | BSD-2-Clause | Linux |
| `arrayvec` | 0.7.8 | MIT OR Apache-2.0 | Both |
| `as-raw-xcb-connection` | 1.0.1 | MIT OR Apache-2.0 | Linux |
| `ashpd` | 0.11.1 | MIT | Linux |
| `async-broadcast` | 0.7.2 | MIT OR Apache-2.0 | Linux |
| `async-channel` | 2.5.0 | Apache-2.0 OR MIT | Linux |
| `async-executor` | 1.14.0 | Apache-2.0 OR MIT | Linux |
| `async-fs` | 2.2.0 | Apache-2.0 OR MIT | Linux |
| `async-io` | 2.6.0 | Apache-2.0 OR MIT | Linux |
| `async-lock` | 3.4.2 | Apache-2.0 OR MIT | Linux |
| `async-net` | 2.0.0 | Apache-2.0 OR MIT | Linux |
| `async-process` | 2.5.0 | Apache-2.0 OR MIT | Linux |
| `async-recursion` | 1.1.1 | MIT OR Apache-2.0 | Linux |
| `async-signal` | 0.2.14 | Apache-2.0 OR MIT | Linux |
| `async-task` | 4.7.1 | Apache-2.0 OR MIT | Linux |
| `async-trait` | 0.1.91 | MIT OR Apache-2.0 | Linux |
| `atomic-waker` | 1.1.2 | Apache-2.0 OR MIT | Linux |
| `bitflags` | 2.13.1 | MIT OR Apache-2.0 | Both |
| `blocking` | 1.6.2 | Apache-2.0 OR MIT | Linux |
| `bytemuck` | 1.25.2 | Zlib OR Apache-2.0 OR MIT | Both |
| `bytemuck_derive` | 1.12.0 | Zlib OR Apache-2.0 OR MIT | Both |
| `calloop` | 0.13.0 | MIT | Linux |
| `calloop-wayland-source` | 0.3.0 | MIT | Linux |
| `cfg-if` | 1.0.4 | MIT OR Apache-2.0 | Both |
| `clap` | 4.6.6 | MIT OR Apache-2.0 | Both |
| `clap_builder` | 4.6.6 | MIT OR Apache-2.0 | Both |
| `clap_derive` | 4.6.4 | MIT OR Apache-2.0 | Both |
| `clap_lex` | 1.1.0 | MIT OR Apache-2.0 | Both |
| `color` | 0.3.3 | Apache-2.0 OR MIT | Both |
| `colorchoice` | 1.0.5 | MIT OR Apache-2.0 | Both |
| `concurrent-queue` | 2.5.0 | Apache-2.0 OR MIT | Linux |
| `constify` | 0.0.1 | MIT OR Apache-2.0 | Both |
| `crossbeam-utils` | 0.8.22 | MIT OR Apache-2.0 | Linux |
| `crossterm` | 0.28.1 | MIT | Both |
| `crossterm_winapi` | 0.9.1 | MIT | Windows |
| `ctor` | 0.10.1 | Apache-2.0 OR MIT | Linux |
| `ctrlc` | 3.5.2 | MIT/Apache-2.0 | Both |
| `cursor-icon` | 1.2.0 | MIT OR Apache-2.0 OR Zlib | Both |
| `displaydoc` | 0.2.7 | MIT OR Apache-2.0 | Linux |
| `dlib` | 0.5.3 | MIT | Linux |
| `downcast-rs` | 1.2.1 | MIT/Apache-2.0 | Linux |
| `dpi` | 0.1.2 | Apache-2.0 AND MIT | Both |
| `drm` | 0.14.1 | MIT | Linux |
| `drm-ffi` | 0.9.1 | MIT | Linux |
| `drm-fourcc` | 2.2.0 | MIT | Linux |
| `drm-sys` | 0.8.1 | MIT | Linux |
| `ecolor` | 0.34.3 | MIT OR Apache-2.0 | Both |
| `egui` | 0.34.3 | MIT OR Apache-2.0 | Both |
| `egui-winit` | 0.34.3 | MIT OR Apache-2.0 | Both |
| `egui_extras` | 0.34.3 | MIT OR Apache-2.0 | Both |
| `egui_software_backend` | 0.0.3 | MIT OR Apache-2.0 | Both |
| `emath` | 0.34.3 | MIT OR Apache-2.0 | Both |
| `endi` | 1.1.1 | MIT | Linux |
| `enum-map` | 2.7.3 | MIT OR Apache-2.0 | Both |
| `enum-map-derive` | 0.17.0 | MIT OR Apache-2.0 | Both |
| `enumflags2` | 0.7.12 | MIT OR Apache-2.0 | Linux |
| `enumflags2_derive` | 0.7.12 | MIT OR Apache-2.0 | Linux |
| `epaint` | 0.34.3 | MIT OR Apache-2.0 | Both |
| `epaint_default_fonts` | 0.34.3 | (MIT OR Apache-2.0) AND OFL-1.1 AND Ubuntu-font-1.0 | Both |
| `equivalent` | 1.0.2 | Apache-2.0 OR MIT | Linux |
| `errno` | 0.3.14 | MIT OR Apache-2.0 | Linux |
| `event-listener` | 5.4.2 | Apache-2.0 OR MIT | Linux |
| `event-listener-strategy` | 0.5.4 | Apache-2.0 OR MIT | Linux |
| `fastrand` | 2.5.0 | Apache-2.0 OR MIT | Linux |
| `fearless_simd` | 0.3.0 | Apache-2.0 OR MIT | Both |
| `foldhash` | 0.2.0 | Zlib | Both |
| `font-types` | 0.11.3 | MIT OR Apache-2.0 | Both |
| `form_urlencoded` | 1.2.2 | MIT OR Apache-2.0 | Linux |
| `futures-channel` | 0.3.33 | MIT OR Apache-2.0 | Linux |
| `futures-core` | 0.3.33 | MIT OR Apache-2.0 | Linux |
| `futures-io` | 0.3.33 | MIT OR Apache-2.0 | Linux |
| `futures-lite` | 2.6.1 | Apache-2.0 OR MIT | Linux |
| `futures-macro` | 0.3.33 | MIT OR Apache-2.0 | Linux |
| `futures-task` | 0.3.33 | MIT OR Apache-2.0 | Linux |
| `futures-util` | 0.3.33 | MIT OR Apache-2.0 | Linux |
| `gethostname` | 1.1.0 | Apache-2.0 | Linux |
| `getrandom` | 0.3.4 | MIT OR Apache-2.0 | Linux |
| `hashbrown` | 0.16.1 | MIT OR Apache-2.0 | Both |
| `hashbrown` | 0.17.1 | MIT OR Apache-2.0 | Linux |
| `heck` | 0.5.0 | MIT OR Apache-2.0 | Both |
| `hex` | 0.4.3 | MIT OR Apache-2.0 | Linux |
| `icu_collections` | 2.2.0 | Unicode-3.0 | Linux |
| `icu_locale_core` | 2.2.0 | Unicode-3.0 | Linux |
| `icu_normalizer` | 2.2.0 | Unicode-3.0 | Linux |
| `icu_normalizer_data` | 2.2.0 | Unicode-3.0 | Linux |
| `icu_properties` | 2.2.0 | Unicode-3.0 | Linux |
| `icu_properties_data` | 2.2.0 | Unicode-3.0 | Linux |
| `icu_provider` | 2.2.0 | Unicode-3.0 | Linux |
| `idna` | 1.1.0 | MIT OR Apache-2.0 | Linux |
| `idna_adapter` | 1.2.2 | Apache-2.0 OR MIT | Linux |
| `indexmap` | 2.14.0 | Apache-2.0 OR MIT | Linux |
| `is_terminal_polyfill` | 1.70.2 | MIT OR Apache-2.0 | Both |
| `kurbo` | 0.13.1 | Apache-2.0 OR MIT | Both |
| `libc` | 0.2.189 | MIT OR Apache-2.0 | Linux |
| `libloading` | 0.8.9 | ISC | Linux |
| `linebender_resource_handle` | 0.1.1 | Apache-2.0 OR MIT | Both |
| `linux-raw-sys` | 0.12.1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | Linux |
| `linux-raw-sys` | 0.4.15 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | Linux |
| `linux-raw-sys` | 0.9.4 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | Linux |
| `litemap` | 0.8.2 | Unicode-3.0 | Linux |
| `lock_api` | 0.4.14 | MIT OR Apache-2.0 | Both |
| `log` | 0.4.33 | MIT OR Apache-2.0 | Both |
| `memchr` | 2.8.3 | Unlicense OR MIT | Linux |
| `memmap2` | 0.9.11 | MIT OR Apache-2.0 | Linux |
| `mime` | 0.3.17 | MIT OR Apache-2.0 | Both |
| `mime_guess2` | 2.3.1 | MIT | Both |
| `mio` | 1.2.2 | MIT | Linux |
| `nix` | 0.31.3 | MIT | Linux |
| `nohash-hasher` | 0.2.0 | Apache-2.0 OR MIT | Both |
| `once_cell` | 1.21.4 | MIT OR Apache-2.0 | Both |
| `once_cell_polyfill` | 1.70.2 | MIT OR Apache-2.0 | Windows |
| `ordered-stream` | 0.2.0 | MIT OR Apache-2.0 | Linux |
| `owned_ttf_parser` | 0.25.1 | Apache-2.0 | Linux |
| `parking` | 2.2.1 | Apache-2.0 OR MIT | Linux |
| `parking_lot` | 0.12.5 | MIT OR Apache-2.0 | Both |
| `parking_lot_core` | 0.9.12 | MIT OR Apache-2.0 | Both |
| `peniko` | 0.6.1 | Apache-2.0 OR MIT | Both |
| `percent-encoding` | 2.3.2 | MIT OR Apache-2.0 | Linux |
| `pin-project-lite` | 0.2.17 | Apache-2.0 OR MIT | Both |
| `piper` | 0.2.5 | MIT OR Apache-2.0 | Linux |
| `polling` | 3.11.0 | Apache-2.0 OR MIT | Linux |
| `pollster` | 0.4.0 | Apache-2.0/MIT | Linux |
| `polycool` | 0.4.0 | MIT OR Apache-2.0 | Both |
| `potential_utf` | 0.1.5 | Unicode-3.0 | Linux |
| `ppv-lite86` | 0.2.21 | MIT OR Apache-2.0 | Linux |
| `proc-macro-crate` | 3.5.0 | MIT OR Apache-2.0 | Linux |
| `proc-macro2` | 1.0.107 | MIT OR Apache-2.0 | Both |
| `profiling` | 1.0.18 | MIT OR Apache-2.0 | Both |
| `quick-xml` | 0.41.0 | MIT | Linux |
| `quote` | 1.0.47 | MIT OR Apache-2.0 | Both |
| `rand` | 0.9.5 | MIT OR Apache-2.0 | Linux |
| `rand_chacha` | 0.9.0 | MIT OR Apache-2.0 | Linux |
| `rand_core` | 0.9.5 | MIT OR Apache-2.0 | Linux |
| `raw-window-handle` | 0.6.2 | MIT OR Apache-2.0 OR Zlib | Both |
| `read-fonts` | 0.37.0 | MIT OR Apache-2.0 | Both |
| `rfd` | 0.15.4 | MIT | Both |
| `rustix` | 0.38.44 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | Linux |
| `rustix` | 1.1.4 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | Linux |
| `scoped-tls` | 1.0.1 | MIT/Apache-2.0 | Linux |
| `scopeguard` | 1.2.0 | MIT OR Apache-2.0 | Both |
| `sctk-adwaita` | 0.10.1 | MIT | Linux |
| `self_cell` | 1.3.0 | Apache-2.0 OR GPL-2.0-only | Both |
| `serde` | 1.0.229 | MIT OR Apache-2.0 | Linux |
| `serde_core` | 1.0.229 | MIT OR Apache-2.0 | Linux |
| `serde_derive` | 1.0.229 | MIT OR Apache-2.0 | Linux |
| `serde_repr` | 0.1.21 | MIT OR Apache-2.0 | Linux |
| `signal-hook` | 0.3.18 | Apache-2.0/MIT | Linux |
| `signal-hook-mio` | 0.2.5 | MIT OR Apache-2.0 | Linux |
| `signal-hook-registry` | 1.4.8 | MIT OR Apache-2.0 | Linux |
| `skrifa` | 0.40.0 | MIT OR Apache-2.0 | Both |
| `slab` | 0.4.12 | MIT | Linux |
| `smallvec` | 1.15.2 | MIT OR Apache-2.0 | Both |
| `smithay-client-toolkit` | 0.19.2 | MIT | Linux |
| `smol_str` | 0.2.2 | MIT OR Apache-2.0 | Both |
| `softbuffer` | 0.4.8 | MIT OR Apache-2.0 | Both |
| `stable_deref_trait` | 1.2.1 | MIT OR Apache-2.0 | Linux |
| `strength_reduce` | 0.2.4 | MIT OR Apache-2.0 | Both |
| `strict-num` | 0.1.1 | MIT | Linux |
| `strsim` | 0.11.1 | MIT | Both |
| `syn` | 2.0.119 | MIT OR Apache-2.0 | Both |
| `syn` | 3.0.3 | MIT OR Apache-2.0 | Both |
| `synstructure` | 0.13.2 | MIT | Linux |
| `terminal_size` | 0.4.4 | MIT OR Apache-2.0 | Both |
| `thiserror` | 1.0.69 | MIT OR Apache-2.0 | Linux |
| `thiserror-impl` | 1.0.69 | MIT OR Apache-2.0 | Linux |
| `tiny-skia` | 0.11.4 | BSD-3-Clause | Linux |
| `tiny-skia-path` | 0.11.4 | BSD-3-Clause | Linux |
| `tiny-xlib` | 0.2.5 | MIT OR Apache-2.0 OR Zlib | Linux |
| `tinystr` | 0.8.3 | Unicode-3.0 | Linux |
| `toml_datetime` | 1.1.1+spec-1.1.0 | MIT OR Apache-2.0 | Linux |
| `toml_edit` | 0.25.13+spec-1.1.0 | MIT OR Apache-2.0 | Linux |
| `toml_parser` | 1.1.3+spec-1.1.0 | MIT OR Apache-2.0 | Linux |
| `tracing` | 0.1.44 | MIT | Both |
| `tracing-attributes` | 0.1.31 | MIT | Linux |
| `tracing-core` | 0.1.36 | MIT | Both |
| `ttf-parser` | 0.25.1 | MIT OR Apache-2.0 | Linux |
| `unicase` | 2.9.0 | MIT OR Apache-2.0 | Both |
| `unicode-ident` | 1.0.24 | (MIT OR Apache-2.0) AND Unicode-3.0 | Both |
| `unicode-segmentation` | 1.13.3 | MIT OR Apache-2.0 | Both |
| `url` | 2.5.8 | MIT OR Apache-2.0 | Linux |
| `urlencoding` | 2.1.3 | MIT | Linux |
| `utf8_iter` | 1.0.4 | Apache-2.0 OR MIT | Linux |
| `utf8parse` | 0.2.2 | Apache-2.0 OR MIT | Both |
| `uuid` | 1.24.0 | Apache-2.0 OR MIT | Both |
| `vello_common` | 0.0.6 | Apache-2.0 OR MIT | Both |
| `vello_cpu` | 0.0.6 | Apache-2.0 OR MIT | Both |
| `wayland-backend` | 0.3.16 | MIT | Linux |
| `wayland-client` | 0.31.15 | MIT | Linux |
| `wayland-csd-frame` | 0.3.0 | MIT | Linux |
| `wayland-cursor` | 0.31.14 | MIT | Linux |
| `wayland-protocols` | 0.32.13 | MIT | Linux |
| `wayland-protocols-plasma` | 0.3.12 | MIT | Linux |
| `wayland-protocols-wlr` | 0.3.12 | MIT | Linux |
| `wayland-scanner` | 0.31.11 | MIT | Linux |
| `wayland-sys` | 0.31.11 | MIT | Linux |
| `web-time` | 1.1.0 | MIT OR Apache-2.0 | Both |
| `winapi` | 0.3.9 | MIT/Apache-2.0 | Windows |
| `windows-link` | 0.2.1 | MIT OR Apache-2.0 | Windows |
| `windows-sys` | 0.48.0 | MIT OR Apache-2.0 | Windows |
| `windows-sys` | 0.52.0 | MIT OR Apache-2.0 | Windows |
| `windows-sys` | 0.59.0 | MIT OR Apache-2.0 | Windows |
| `windows-sys` | 0.61.2 | MIT OR Apache-2.0 | Windows |
| `windows-targets` | 0.48.5 | MIT OR Apache-2.0 | Windows |
| `windows-targets` | 0.52.6 | MIT OR Apache-2.0 | Windows |
| `windows_x86_64_msvc` | 0.48.5 | MIT OR Apache-2.0 | Windows |
| `windows_x86_64_msvc` | 0.52.6 | MIT OR Apache-2.0 | Windows |
| `winit` | 0.30.13 | Apache-2.0 | Both |
| `winnow` | 1.0.4 | MIT | Linux |
| `winreg` | 0.52.0 | MIT | Windows |
| `writeable` | 0.6.3 | Unicode-3.0 | Linux |
| `x11-dl` | 2.21.0 | MIT | Linux |
| `x11rb` | 0.13.2 | MIT OR Apache-2.0 | Linux |
| `x11rb-protocol` | 0.13.2 | MIT OR Apache-2.0 | Linux |
| `xcursor` | 0.3.11 | MIT | Linux |
| `xkbcommon-dl` | 0.4.2 | MIT | Linux |
| `xkeysym` | 0.2.1 | MIT OR Apache-2.0 OR Zlib | Linux |
| `yoke` | 0.8.3 | Unicode-3.0 | Linux |
| `yoke-derive` | 0.8.2 | Unicode-3.0 | Linux |
| `zbus` | 5.18.0 | MIT | Linux |
| `zbus_macros` | 5.18.0 | MIT | Linux |
| `zbus_names` | 4.3.4 | MIT | Linux |
| `zerocopy` | 0.8.56 | BSD-2-Clause OR Apache-2.0 OR MIT | Both |
| `zerofrom` | 0.1.8 | Unicode-3.0 | Linux |
| `zerofrom-derive` | 0.1.7 | Unicode-3.0 | Linux |
| `zerotrie` | 0.2.4 | Unicode-3.0 | Linux |
| `zerovec` | 0.11.6 | Unicode-3.0 | Linux |
| `zerovec-derive` | 0.11.3 | Unicode-3.0 | Linux |
| `zvariant` | 5.13.1 | MIT | Linux |
| `zvariant_derive` | 5.13.1 | MIT | Linux |
| `zvariant_utils` | 3.5.0 | MIT | Linux |

## Regenerating this list

```bash
cargo tree --workspace -e normal --target x86_64-unknown-linux-gnu \
  --prefix none --format "{l}|{p}" | sort -u
cargo tree --workspace -e normal --target x86_64-pc-windows-msvc \
  --prefix none --format "{l}|{p}" | sort -u
```

`Cargo.lock` is committed, so these commands are reproducible. Re-run them
after any dependency change and update the table above.
