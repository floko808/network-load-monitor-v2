---
name: network-load-monitor-v2
description: Complete build spec for recreating Network Load Monitor V2, the Rust IEC 61850 network analyser — a workspace that captures raw Ethernet frames, classifies substation-automation protocols (GOOSE/SV/R-GOOSE/PTP/MMS/DNP3/IEC104/Modbus), detects HSR/PRP redundancy and VLAN tagging, and reports live throughput/link-load through a terminal UI and an egui desktop UI, cross-compiled for Linux and Windows.
---

# Network Load Monitor V2 (Rust) — recreation guide

This document is a self-contained spec for rebuilding this project from
scratch with any capable LLM/coding agent, without access to the repository.
It captures the architecture, every byte-level parsing rule, the CLI/GUI
behaviour, and the cross-compilation steps. Follow it top to bottom.

It supersedes the spec for the Python implementation that preceded it. Where the two differ, the
differences are called out explicitly in §16 — several are bug fixes, not
translation choices, and reproducing the Python behaviour there would
reproduce known defects.

## 1. What the tool does

A network-load/protocol analyser purpose-built for IEC 61850 substation
automation networks. It:

- Captures raw Ethernet frames on a NIC, or reads an existing `.pcap`/
  `.pcapng` file.
- Classifies each frame by protocol, VLAN tag(s), 802.1Q CoS/PCP, and
  HSR/PRP redundancy lane.
- For GOOSE / Sampled Values / R-GOOSE, decodes the application header
  (AppID, GOOSE-ID/SVID, stNum/noASDU, confRev, simulation flag) with a
  hand-rolled ASN.1 BER walk — no ASN.1 library.
- For MMS / DNP3 / IEC104 / Modbus TCP, confirms the well-known port against
  the protocol's own framing signature before classifying. A port match alone
  is never trusted.
- Aggregates everything else (ARP, LLDP, RSTP, NTP, IPv4/IPv6, R-SV, GSSE,
  unclassified) into a single "Other" row.
- Computes bits/second and percentage of a configurable link speed over a
  rolling window.
- Ships two front ends over one shared engine crate: a terminal UI and a
  desktop UI that renders on the CPU, so it needs no graphics driver and runs
  in a virtual machine.
- Runs without root by falling back from a raw `AF_PACKET` socket to
  Wireshark's `dumpcap` helper.
- Cross-compiles to single-file Linux and Windows binaries with no runtime
  installation required on the target machine.

License: `MIT`. Unlike the Python original there is no GPL dependency to
inherit from — see §14.

## 2. Project layout

A Cargo workspace with one engine crate and two front-end crates:

```
Cargo.toml                       # workspace root, shared profile + metadata
build.sh                         # test + cross-build both targets into dist/
crates/
  nlm-core/                      # the engine. No UI, no I/O policy.
    src/consts.rs                # EtherTypes, ports, defaults, batching knobs
    src/parse.rs                 # frame classifier + BER walkers   (~1100 lines)
    src/filter.rs                # pre-count FrameFilter
    src/stats.rs                 # rolling windows, batching, snapshots
    src/report.rs                # snapshot -> table rows (shared by both UIs)
    src/pcap.rs                  # pcap + pcapng readers, offline loading
    src/capture.rs               # AF_PACKET and dumpcap backends, FrameSink
    src/iface.rs                 # interface enumeration
    src/fmt.rs                   # byte/bit/duration formatting
  nlm-cli/                       # binary: network-monitor
    src/main.rs                  # argument surface + run loops
    src/table.rs                 # ASCII panel rendering with ANSI colour
  nlm-gui/                       # binary: network-monitor-gui (CPU-rendered)
    src/main.rs                  # window bootstrap + panic dialog
    src/app.rs                   # the egui application
    src/filter_popup.rs          # per-column value filter state
```

**The single most important structural rule**: the front ends contain no
protocol knowledge and no table logic. `nlm-core::report::build_report` turns
a statistics snapshot into an ordered list of rows — including subtotals, the
"Other" aggregation, idle rows and the grand total — and each front end only
decides how a row is *painted*. The Python original carried this logic twice
and the two copies drifted. Do not reintroduce that split.

## 3. Dependencies

Deliberately minimal. All protocol parsing, all capture-file reading and the
raw-socket backend are implemented directly.

| Crate | Where | Used for |
|---|---|---|
| `libc` | core (unix) | `AF_PACKET` socket, `if_nametoindex`, socket options |
| `winreg` | core (windows) | locating Wireshark via `HKLM\SOFTWARE\Wireshark` |
| `clap` (derive, wrap_help) | cli | argument parsing and help |
| `crossterm` | cli | cursor/screen control, cross-platform ANSI colour |
| `ctrlc` | cli | SIGINT/SIGTERM handling |
| `egui` / `egui_extras` | gui | widgets and the results table |
| `egui_software_backend` | gui | CPU rasteriser + window; no GPU API at all |
| `rfd` | gui | native file/save dialogs and the panic message box |

There is **no** packet-capture library dependency. This is what allows the
permissive license, and it is also what makes offline loading roughly two
orders of magnitude faster than the Python original (§15).

Release profile: `opt-level = 3`, `lto = "thin"`, `codegen-units = 1`,
`strip = true`, `panic = "abort"`.

## 4. Constants (`consts.rs`)

```rust
pub const ET_VLAN:  u16 = 0x8100;  // IEEE 802.1Q
pub const ET_QINQ:  u16 = 0x88A8;  // 802.1ad QinQ
pub const ET_GOOSE: u16 = 0x88B8;  // IEC 61850-8-1
pub const ET_SV:    u16 = 0x88BA;  // IEC 61850-9-2
pub const ET_GSSE:  u16 = 0x88B9;  // legacy GSSE (UCA 2.0)
pub const ET_PTP:   u16 = 0x88F7;  // IEEE 1588
pub const ET_HSR:   u16 = 0x892F;  // IEC 62439-3 HSR in-frame tag
pub const ET_IPV4:  u16 = 0x0800;
pub const ET_IPV6:  u16 = 0x86DD;
pub const ET_ARP:   u16 = 0x0806;
pub const ET_LLDP:  u16 = 0x88CC;
pub const PRP_SUF:  u16 = 0x88FB;  // PRP RCT suffix, last 2 bytes of frame

pub const PORT_MMS: u16 = 102;     pub const PORT_NTP:    u16 = 123;
pub const PORT_MODBUS: u16 = 502;  pub const PORT_IEC104: u16 = 2404;
pub const PORT_DNP3: u16 = 20000;

pub const DEFAULT_LINK_MBPS: f64 = 100.0;
pub const DEFAULT_DURATION_S: f64 = 10.0;   // 0 = run until stopped
pub const DEFAULT_REFRESH_S: f64 = 1.0;
pub const BATCH_PKTS: usize = 200;
pub const BATCH_SECS: f64 = 0.10;
pub const PCAP_PROGRESS_EVERY: u64 = 2000;
```

Protocols eligible for a detail row, in fixed display order:

```rust
pub const PROTO_ORDER: [Protocol; 8] = [
    Goose, SampledValues, RGoose, Ptp, Mms, Dnp3, Iec104, ModbusTcp,
];
```

`Protocol` is an enum covering those eight plus `RSv, Gsse, Ntp, Lldp, Rstp,
Arp, Ipv4, Ipv6, Other`. The latter group is recognised precisely but always
renders as "Other" — keeping them distinct internally costs nothing and means
the classifier never has to guess.

## 5. Frame classification — `parse_frame(&[u8]) -> Frame`

Single entry point for both live capture and file loading.

```rust
pub struct Frame {
    pub proto: Protocol,
    pub vlans: VlanTags,        // fixed-size, Copy, no allocation
    pub redundancy: Redundancy, // None | Hsr(nibble) | Prp(nibble)
    pub app: AppInfo,           // appid/svid/noasdu/confrev/sim, all Option
}
```

Using typed `Option` fields rather than `"-"` sentinel strings matters: the
placeholder is a *display* concern, applied by `*_label()` accessors, so
filtering and comparison never depend on string formatting.

Frames shorter than 14 bytes (a full Ethernet header) return the default
`Frame` immediately.

### 5.0 Byte helpers

Every accessor is bounds-checked. A truncated or hostile frame must only ever
produce a less-populated row, never a panic.

```rust
fn u16be(data: &[u8], off: usize) -> Option<u16>   // None past the end
fn be_uint(bytes: &[u8]) -> u64                    // saturates at u64::MAX
fn ber_string(bytes: &[u8]) -> Box<str>            // non-printable -> '.'
fn ber_len(data: &[u8], off: usize) -> (usize, usize)  // (length, consumed)
fn read_tlv(data: &[u8], off: usize, end: usize) -> Option<Tlv>
```

`ber_len`: short form (`< 0x80`) is the length itself; long form has the high
bit set with the low 7 bits giving the count of big-endian length bytes that
follow. Over-long lengths saturate rather than wrap, and every caller bounds
the resulting offset against the buffer, so a saturated value simply fails
that check.

`ber_string` replacing non-printable bytes is a security control, not
cosmetics: these strings are rendered into a terminal table, and a frame
carrying escape sequences must not be able to move the cursor.

`read_tlv` returns `None` when the element's own length runs past the
enclosing `end`, which is the single guard that makes all four BER walkers
safe against truncation.

### 5.1 VLAN / QinQ tags (a loop, not a single check)

```
off = 12; etype = u16be(off); off += 2
while etype in {0x8100, 0x88A8} and off + 4 <= len:
    pcp     = (data[off] >> 5) & 0x07
    vlan_id = ((data[off] & 0x0F) << 8) | data[off+1]
    push(vlan_id, pcp)
    etype = u16be(off + 2)
    off += 4
```

Looping is what makes QinQ work. `VlanTags` holds up to 4 tags inline;
`vlan_label()` and `cos_label()` comma-join them or return `-`.

### 5.2 HSR in-frame tag (IEC 62439-3 §5), EtherType `0x892F`

Six bytes follow the EtherType: Path (high nibble) + LSDUsize (12 bits),
SeqNr, then the embedded EtherType — the real inner protocol.

```
if etype == 0x892F and off + 6 <= len:
    redundancy = Hsr((data[off] >> 4) & 0x0F)
    etype = u16be(off + 4)
    off += 6
```

Display: nibble `0xA` → `HSR-A`, `0xB` → `HSR-B`, anything else → `HSR-0x<n>`
(report it rather than dropping it).

### 5.3 PRP Redundancy Control Trailer (IEC 62439-3 §4)

PRP has no inline tag. A 6-byte trailer sits at the **end** of the frame:
SeqNr, LanId (high nibble) + LSDUsize, then the suffix `0x88FB`.

```
if redundancy == None and len >= 6 and u16be(len - 2) == 0x88FB:
    redundancy = Prp((data[len - 4] >> 4) & 0x0F)
```

PRP does **not** change `etype` or `off` — it wraps a normal frame rather than
nesting a new EtherType the way HSR does. HSR is checked first, so an HSR
frame that happens to end in those two bytes stays HSR.

### 5.4 Payload classification by the resolved EtherType

```
0x88B8 -> Goose,         app = parse_goose_payload(data, off)
0x88BA -> SampledValues, app = parse_sv_payload(data, off)
0x88B9 -> Gsse    0x88F7 -> Ptp    0x88CC -> Lldp    0x0806 -> Arp
0x0800 -> classify_ipv4(data, off)   (may yield an R-GOOSE payload offset)
0x86DD -> Ipv6
n <= 1500 -> IEEE 802.3 length field, not an EtherType.
             DSAP == SSAP == 0x42 is the LLC SAP for STP/RSTP/MSTP -> Rstp
             otherwise -> Other
_ -> Other
```

### 5.5 GOOSE APDU — `parse_goose_payload`

8-byte header at `off`: AppID (u16), Length (u16), Reserved1, Reserved2. The
top bit of Reserved1 (`data[off+4] & 0x80`) is the simulation flag.

Then a `goosePdu` under BER tag `0x61` (APPLICATION 1):

```
80 <len> <str>  gocbRef [0] VisibleString   (fallback)
83 <len> <str>  goID    [3] VisibleString   (preferred when present)
85 <len> <int>  stNum   [5] INTEGER
88 <len> <int>  confRev [8] INTEGER
```

Verify the byte at `off + 8` is `0x61`, consume its BER length to get `end`,
then walk TLVs to `end`, ignoring unknown tags. Collect gocbRef and goID into
*separate* variables and prefer goID at the end — "first one wins" is wrong
because `0x80` precedes `0x83` in the PDU.

If the `0x61` check fails, return the AppID alone and leave every other field
empty, including `sim`. Reporting a simulation flag from a header that turned
out not to precede a goosePdu would be a guess.

### 5.6 Sampled Values APDU — `parse_sv_payload`

Same 8-byte header shape. Then a `savPdu` under BER tag `0x60`
(APPLICATION 0):

```
80 <len> <int>       noASDU    [0] IMPLICIT INTEGER
A2 <len>             seqOfAsdu [2]
  30 <len>           ASDU SEQUENCE (only the first is inspected)
    80 <len> <str>   svID    [0] IMPLICIT VisibleString
    83 <len> <int>   confRev [3] IMPLICIT INTEGER
```

Note `0x80` means noASDU at the top level but svID inside an ASDU — use two
separate walk functions rather than one shared tag match. Only the first ASDU
is decoded: single-ASDU is overwhelmingly the field case, and a multi-ASDU
stream shares svID and confRev across its ASDUs anyway.

### 5.7 IPv4 — `classify_ipv4(data, ip_off) -> (Protocol, Option<usize>)`

The optional `usize` is the UDP payload offset, returned only for R-GOOSE.

```
if ip_off + 20 > len: return (Ipv4, None)
frag_off = ((data[ip_off+6] & 0x1F) << 8) | data[ip_off+7]
if frag_off != 0: return (Ipv4, None)   // no transport header to inspect
ip_proto = data[ip_off+9]
ihl      = (data[ip_off] & 0x0F) * 4
t_off    = ip_off + ihl
```

**TCP** (proto 6): read sport/dport; the payload starts at
`t_off + doff*4` where `doff = (data[t_off+12] >> 4) & 0x0F`, requiring
`doff >= 5`. Then, in order:

```
102   + looks_like_mms      -> Mms
2404  + looks_like_iec104   -> Iec104
502   + looks_like_modbus   -> ModbusTcp
20000 + looks_like_dnp3     -> Dnp3
otherwise                   -> Ipv4
```

**UDP** (proto 17): port 123 → `Ntp`. Port 20000 with a DNP3 signature →
`Dnp3`. Then multicast handling (§5.8).

Signature checks — the port is only a hint:

```rust
fn looks_like_mms(p)    -> p.len() >= 4 && p[0]==0x03 && p[1]==0x00 && u16be(p,2) >= 4
fn looks_like_iec104(p) -> p.len() >= 2 && p[0]==0x68 && (4..=253).contains(&p[1])
fn looks_like_modbus(p) -> p.len() >= 8 && u16be(p,2)==0 && (2..=253).contains(&u16be(p,4)) && p[7]!=0
fn looks_like_dnp3(p)   -> p.len() >= 3 && p[0]==0x05 && p[1]==0x64 && p[2] >= 5
```

If the port matches but the signature does not, the frame stays `Ipv4` and
folds into "Other". Never force-classify by port alone.

### 5.8 R-GOOSE / R-SV over UDP multicast (IEC 61850-8-2 / 9-3)

Membership of `224.0.0.0/4` is **not** sufficient on its own — that range also
carries mDNS (`224.0.0.251`), SSDP (`239.255.255.250`), IGMP and every other
ordinary IP multicast. Confirm the payload first, exactly as the unicast
protocols must match their own framing:

```
if dst[0] & 0xF0 == 0xE0:
    if find_session_pdu(data, udp_off, 0x61).is_some(): -> RGoose (with payload offset)
    if find_session_pdu(data, udp_off, 0x60).is_some(): -> RSv
    // fallback for a session header longer than the scan window:
    if dst[0] == 224 && dst[1] == 0 && dst[2] == 1: -> RGoose
    if dst[0] == 224 && dst[1] == 0 && dst[2] == 2: -> RSv
    otherwise -> Ipv4
```

The address fallback is deliberately narrow — only `224.0.1.0/24` and
`224.0.2.0/24`, which no general-purpose multicast protocol uses.

`find_session_pdu(data, udp_off, tag)` scans `udp_off+4 .. udp_off+128` for
`tag`, accepting a candidate only when its BER length is plausible
(`0 < len < 0x8000`) **and** the following byte is `0x80` — the tag that
always opens a PDU body. That second condition is what rejects incidental tag
bytes inside the vendor-varying Session PDU header.

`parse_rgoose_payload` then reads AppID from the 2 bytes at
`tag_offset - 4` (the R-GOOSE APDU header is only AppID + Length, 4 bytes)
and walks the body for `0x80` gocbRef, `0x83` goID, `0x85` stNum, `0x88`
confRev, plus `0x87` simulation `[7] BOOLEAN` — R-GOOSE has no Reserved1 to
carry the sim flag, so it appears as a PDU field instead. Default `sim` is
false when tag `0x87` is absent.

## 6. Pre-count filter (`filter.rs`)

`FrameFilter` holds four independent, all-optional constraints: `vlans`,
`redundancy`, `appids`, `svids`. Values within one field OR; different fields
AND. Filtering happens **before counting**, so a filtered frame never touches
any total, the table, or the session summary.

- `--vlan` matches **any** tag in a stacked (QinQ) frame, not just the outermost.
- `--redundancy` accepts `{hsr, prp, none, hsr-a, hsr-b, prp-a, prp-b}`. A
  frame's redundancy expands to a token set — `Hsr(0xA)` → `{hsr, hsr-a}`,
  `None` → `{none}` — which is what lets `hsr` match either lane while
  `hsr-a` stays specific. Validate against the token list at parse time and
  fail with a clear message.
- `--appid` parses hex with or without `0x`, compared numerically.
- `--goid` and `--svid` both populate `svids`, matched uppercased. A frame is
  either GOOSE or SV, never both, so sharing the column is unambiguous.

All parsing is validated up front, so a typo fails before a capture starts
rather than silently matching nothing.

## 7. Capture backends (`capture.rs`)

Frames are delivered to a `FrameSink`, not a closure:

```rust
pub trait FrameSink: Send + 'static {
    fn frame(&mut self, data: &[u8], wire_len: u64);
    fn idle(&mut self) {}    // no frame within the poll interval
    fn finish(&mut self) {}  // capture ending, flush anything buffered
}
```

`idle` and `finish` are load-bearing, not decoration. Without them the tail of
a burst sits in a half-full batch until the *next* burst arrives — landing in
the wrong window, potentially minutes later, on exactly the sparse protocols
where accuracy matters most.

`StatsSink` implements it: parse → filter → fold into a thread-local
`BatchAccum` → merge under lock when full.

Backend selection, in order:

1. **Raw `AF_PACKET` socket** (Linux). Availability is decided by *trying to
   open one*, never by checking for uid 0 — `CAP_NET_RAW` can be granted to
   an unprivileged binary and a uid check would wrongly send those users down
   the fallback path. Bind to the interface index, set `SO_RCVBUF` to 8 MB
   (the kernel drops frames long before the classifier is the bottleneck) and
   `SO_RCVTIMEO` to 200 ms so a stop request is acted on promptly on a silent
   link. A receive timeout calls `sink.idle()`.
2. **`dumpcap`**, spawned as `dumpcap -i <iface> -w - -F pcap -q` with stdout
   piped into the pcap reader (§8). Located via `PATH`, then on Windows the
   standard install directories and finally `HKLM\SOFTWARE\Wireshark` /
   `...\WOW6432Node\Wireshark` `InstallDir`, because the Wireshark installer
   does not add itself to `PATH`.
   Capture stderr rather than discarding it: when `dumpcap` cannot open the
   interface, its own message is far more useful than "the stream was
   unreadable".
3. **Neither** → a platform-specific, actionable error naming concrete
   remedies (`sudo`, `setcap cap_net_raw+eip`, the `wireshark` group; or on
   Windows installing Wireshark and lifting Npcap's admin-only restriction).
   Never silently capture nothing.

`Capture::is_running()` stays true briefly after `stop()`, because `dumpcap`
buffers and frames captured moments earlier may still be in flight. Both front
ends wait up to 5 seconds for it to clear before the final render; the bound
exists so a backend that fails to exit cannot hang the UI.

## 8. Capture-file readers (`pcap.rs`)

One streaming `CaptureReader<R: Read>` serves both the live `dumpcap` pipe and
offline files, handling classic pcap and pcapng.

**Magic-byte validation comes before anything else** and is a security
control, not just validation. A general capture library will transparently
decompress a gzip-wrapped file with no size cap, so a small crafted `.gz`
renamed to `.pcap` could expand into an effectively unbounded stream. Plain
pcap and pcapng have no such amplification — bytes read equal bytes on disk —
so refusing everything else closes that path without limiting legitimately
large captures. Check the real header, never the extension or a file picker's
type filter.

Accepted magics, read as a little-endian u32:

```
0xa1b2c3d4 -> LE, microsecond      0xa1b23c4d -> LE, nanosecond
0xd4c3b2a1 -> BE, microsecond      0x4d3cb2a1 -> BE, nanosecond
plus pcapng's 0x0A0D0D0A section header, either byte order
```

Classic pcap: 24-byte global header (reject link types other than
`LINKTYPE_ETHERNET = 1`, which would otherwise misparse into nonsense), then
16-byte records (`ts_sec, ts_frac, incl_len, orig_len`) each followed by
`incl_len` frame bytes.

pcapng: walk blocks (type, total length, body, trailing length). Handle SHB
(byte order, and a new section resets interface numbering), IDB (link type
plus the `if_tsresol` option, code 9 — value with the high bit set means
`2^-n`, otherwise `10^-n`, defaulting to microseconds), EPB, SPB and the
legacy Packet Block. Skip packets from non-Ethernet interfaces rather than
misparsing them.

Two bounds guard against corrupt or hostile input: `MAX_FRAME_LEN = 262_144`
and `MAX_BLOCK_LEN = 16 MiB`.

Reads must loop (`read_full`) rather than assume one syscall fills the
buffer — on a pipe from `dumpcap`, a single read can return a partial record
header. A short read or clean EOF at any point ends the stream quietly; it is
not an error.

`load_file(path, filter, progress)` accumulates a `StatsMap`, tracks
`t_min`/`t_max` for `duration_s`, and calls `progress(packets, bytes, percent)`
every 2000 packets and once at completion. Percent comes from the reader's
byte position against the file size. Returning `false` from the callback
aborts the load, which is how the GUI cancels.

Frame size uses `orig_len` (the wire length), not the captured length: a
snaplen-truncated frame still occupied its full size on the link being
measured.

### 8.1 Link speed

The `%` column is only as meaningful as the link speed it divides by, so the
speed must be *detected*, never assumed. `/sys/class/net/<if>/speed` on Linux
(it reads `-1` when the link is down and errors on Wi-Fi, both of which mean
"unknown"); `GetAdaptersAddresses` from the IP Helper API on Windows, matched
to `dumpcap`'s `\Device\NPF_{GUID}` device path by adapter GUID. Reject the
`0` and `u64::MAX` values Windows reports for "unknown".

Fall back to 100 Mb/s only when nothing is detectable, and **say so** — the
terminal build prints whether the figure was detected, given, or assumed.
Silently assuming 100 Mb/s on a gigabit link reports every percentage ten
times too high, which is worse than useless in a tool whose entire job is
reporting link load. A capture file carries no link speed at all, so offline
loading always depends on the flag.

## 9. Statistics (`stats.rs`)

Three sets of counters, because each answers a question the others cannot:

- **current** — the window still filling. Never displayed, so the table cannot
  race a half-collected window and show a dip that is not real.
- **display** — a snapshot of the last *completed* window. All rates come from
  this.
- **session** — cumulative for the whole run, never rotated. At the moment a
  capture stops, the final window may be empty for a bursty protocol that
  carried plenty of traffic earlier; without this there is nothing honest to
  put in a summary.

Plus `last_active` / `last_active_at`: the last non-empty window per protocol
and when it was seen. A sparse protocol's rows stay on screen between bursts,
rendered dim with `0.000 bit/s` and `idle Ns` in place of the percentage.
A row vanishing the instant traffic pauses looks identical to "never
detected", which is materially misleading to an operator.

`StatKey` — everything that distinguishes one row within a protocol:
`(VlanTags, Redundancy, AppInfo)`. Two frames of the same protocol differing
in any of these get separate rows.

Rotation, under lock: move current → display, and record any non-empty
protocol into `last_active`.

The window duration is `max(wall-clock elapsed, capture-time span of the
frames in that window, 0.001)`. The two differ whenever a backend hands over
frames in bursts rather than as they were captured — which is exactly what a
`dumpcap` pipe does, and on Windows that is the only backend there is. Ten
seconds of buffered traffic landing in a one-second window would otherwise be
reported at ten times the real load. Taking the longer of the two also covers
the opposite case: two frames a millisecond apart are a trickle across the
window, not a burst measured over a millisecond. This is the reason
`FrameSink::frame` carries a timestamp at all (§7).

`BatchAccum` is the thread-local pre-aggregator: capture threads fold frames
in without touching a lock and hand over the whole batch at once, flushing
after `BATCH_PKTS` (200) **or** `BATCH_SECS` (0.10), whichever comes first.
Both bounds matter — the packet bound keeps the lock cold at Sampled Values
rates, the time bound stops a quiet network waiting 200 frames to show
anything. At SV rates a stream collapses to a single key, so 200 frames become
one merge instead of 200.

## 10. Report building (`report.rs`)

`build_report(&Snapshot, &enabled, link_mbps, &DisplayFilter) -> Report`.

Columns, in order: `Protocol, VLAN, CoS, Redundancy, AppID, SVID/GOID,
noASDU/stNum, confRev, Sim, bits/s, %`.

Row kinds: `Detail`, `Idle`, `Subtotal`, `Other`, `Total`.

Algorithm:

1. For each protocol in `PROTO_ORDER`: if not enabled, add its bytes to the
   "Other" accumulator. If enabled and it has rows this window, emit them
   sorted; if it has none but appears in `idle`, emit its last-known rows as
   `Idle`. Add a `Sum <protocol>` subtotal **only when more than one row is
   shown** — a subtotal over one row says nothing.
2. Fold every non-`PROTO_ORDER` protocol into "Other". Emit that row only if
   its byte count is non-zero.
3. Emit `TOTAL` as the sum of everything actually shown.

`rate = bytes * 8 / window_secs`; `pct = rate / (link_mbps * 1e6) * 100`.
`LoadLevel::of(pct)`: `> 70` critical, `> 40` warn, else normal.

Format the percentage with **scaled precision**, not fixed decimals. Traffic
on one substation link spans orders of magnitude: a Sampled Values stream sits
around 10%, while GOOSE and PTP background traffic on the same 100 Mb/s link
sits near 0.001%. At two fixed decimals every one of those rows prints `0.00`
while their total prints `0.01`, which reads as a broken column and as parts
that do not add up. Roughly three significant digits (`>=10` → 2 dp, `>=1` →
3 dp, `>=0.01` → 4 dp, else 6 dp), trailing zeros trimmed to a minimum of two
decimals, and `<0.0001` for anything smaller so it stays distinct from a
genuine zero.

`DisplayFilter` is the GUI's post-hoc column filter (column index → allowed
values). Filtered rows are excluded from subtotals and the total, so the
figures always match what is on screen — but `seen_values` still records every
value encountered, so the dropdown keeps offering values currently filtered
out.

## 11. Terminal front end (`nlm-cli`)

### 11.1 Arguments

```
network-monitor [INTERFACE] [-d SEC] [-s MBPS] [-r SEC] [-l] [-V] [--pcap FILE]
                [--goose] [--sv] [--rgoose] [--ptp]
                [--mms] [--dnp3] [--iec104] [--modbus] [--all]
                [--vlan ID,...] [--redundancy VALUE,...]
                [--appid HEX,...] [--goid ID,...] [--svid ID,...]
```

Defaults: `eth0`, 10 s, 100 Mb/s, 1.0 s window. `--all` is exactly the union
of the eight detail flags. The long help carries a substantial epilog
documenting protocol identification, the bursty-protocol caveat, table
columns, filter semantics, capture backends and worked examples — that text
is load-bearing operator documentation, not decoration.

### 11.2 Flow

`--list` → enumerate and exit. `--pcap` → load with a progress bar on stderr,
print one static panel, exit. Otherwise: resolve the interface, select a
backend, print a one-line banner, start capture, install signal handlers, then
loop — rotating every `refresh` seconds and redrawing at
`max(2.0, 2/refresh)` Hz — until interrupted, the duration elapses, or the
backend stops. Then stop, wait for drain, and do **one final render swapped to
the session total**, replacing the panel in place rather than printing a
second table below it.

### 11.3 Rendering

An ASCII panel with ANSI colour. Column widths come from the content; the box
width is `max(table width, footer width, 40)`, expanded to fill a wider
terminal. Padding is computed on *visible* length (escape sequences stripped),
which is what keeps the right border aligned.

Colour: per-column tints; `Sim = yes` bold red; a non-empty redundancy cell
bold magenta; the `%` cell bold red above 70 and bold yellow above 40;
subtotal and idle rows dim; `TOTAL` bold.

**Windows console rule**: emit plain ASCII only — no box-drawing characters,
no `∑` (use `Sum `), no `∞` (use `forever`). A legacy `cp1252` console cannot
encode them and rendering fails outright rather than substituting `?`. There
is a test asserting the whole panel is ASCII; keep it.

## 12. Desktop front end (`nlm-gui`)

An `egui` window, 1480×620 default, rendered on the CPU (see below). Top to bottom: menu bar
(`Help → About`); toolbar (interface combo, link speed, duration, Start/Stop,
Open pcap/pcapng, Export CSV); detail checkboxes per protocol plus Clear
Filters; the table; a status bar.

**Render on the CPU. Do not use a GPU backend.** This is the single most
important decision in the desktop front end, and it is not a preference.

Substation tooling gets run in virtual machines, and a Hyper-V guest exposes
no OpenGL beyond 1.1 *and* no Direct3D adapter. Three approaches were tried in
order, and the first two do not work:

1. **OpenGL (`eframe` + `glow`)** — fails outright: "egui_glow requires
   opengl 2.0+".
2. **Direct3D 12 / Vulkan (`eframe` + `wgpu`)** — fails with "no suitable
   adapter found". wgpu looks like the escape hatch and is not: there is
   nothing to enumerate on a GPU-less guest, and `egui-wgpu` hardcodes
   `force_fallback_adapter: false`, so it cannot even ask for a software
   adapter.
3. **Bundling Mesa's llvmpipe software OpenGL** — works around the driver
   problem, but costs ~59 MB of DLLs (`opengl32.dll` +
   `libgallium_wgl.dll`) sitting beside the executable. That is no longer a
   portable single binary, and it crashed on the target machine anyway.

What holds is `egui_software_backend`: a pure-Rust CPU rasteriser over
`winit` + `softbuffer`, blitting through GDI on Windows and X11/Wayland on
Linux. `eframe` is dropped entirely. The result imports no OpenGL, Direct3D,
Vulkan or C-runtime library — only core Windows DLLs — and is a single 4.7 MB
file, smaller than the GPU build it replaced.

Assert this in the build script rather than trusting it: check the Windows
binaries' import tables for `opengl32|d3d12|d3d11|dxgi|vulkan|VCRUNTIME|
api-ms-win-crt` and fail the build on a hit. A dependency added by an
innocuous crate upgrade would otherwise silently break every VM deployment.

The app is structured as `egui_software_backend::App`, whose `ui(&mut self,
ui: &mut Ui, _)` receives a root `Ui` rather than a `Context`. Panels therefore
use `show_inside(ui, …)`; free-floating windows and repaint scheduling still
go through `ui.ctx()`.

Key behaviours:

- The `Report` is rebuilt **every frame** from the held snapshot, so detail
  toggles and column filters take effect instantly rather than at the next
  capture tick.
- Selecting an interface defaults the link speed to the OS-reported
  negotiated speed when there is one.
- Filterable column headers (`Protocol, VLAN, Redundancy, AppID, SVID/GOID`)
  are buttons opening a checklist window with `(Select All)` and OK / Clear /
  Cancel. Everything checked stores `None` rather than an all-inclusive set,
  so a header never advertises a filter that filters nothing. An active
  filter marks its header with `▾`.
- Opening a capture file spawns a **background thread**; a modal progress
  window shows percent, packet count and bytes, with a working Cancel. A
  large file must never block the UI thread.
- Stop sets a `stopping` timestamp and waits for `Capture::is_running()` to
  clear (up to 5 s) before the final session-total render.
- CSV export writes exactly the rows on screen, so the file matches what was
  seen, defaulting to `network_monitor_YYYYMMDD_HHMMSS.csv`.
- A panic hook shows a native message box. The Windows build is linked as a
  GUI-subsystem binary with no console and no stderr, so without this a crash
  would make the window vanish with no explanation.

The GUI deliberately does **not** expose the CLI's pre-count filters. Its use
case is interactive drill-down on already-captured data; the CLI's is scripted
capture where dropping unwanted frames early saves memory and keeps output
focused.

## 13. Building and packaging

```bash
./build.sh            # test, then build both targets into dist/
./build.sh linux
./build.sh windows
./build.sh test
```

Windows cross-compilation from Linux uses `cargo-xwin`, which needs no root
and no distribution packages:

```bash
cargo install cargo-xwin
rustup target add x86_64-pc-windows-msvc
cargo xwin build --release --workspace --target x86_64-pc-windows-msvc
```

On first use it downloads the Microsoft CRT and Windows SDK headers/import
libraries into the cargo cache; later builds are offline. The MSVC target is
preferred over `x86_64-pc-windows-gnu` because it needs no mingw toolchain
installed system-wide, and because `rfd` links against the Windows SDK
directly.

Four artifacts, each a single self-contained executable with no runtime to
install: `network-monitor` / `network-monitor-gui` and their `.exe`
counterparts. Confirm the subsystems are right — the CLI must be a console
PE32+ and the GUI a GUI-subsystem PE32+, or the desktop binary will open a
stray console window. `build.sh` smoke-tests what it builds (running the
`.exe`s under `wine` when available) and writes `SHA256SUMS`.

Runtime capture-driver requirement on Windows regardless of front end:
Wireshark (which bundles Npcap) must be installed, and either run elevated or
uncheck Npcap's "Restrict Npcap driver's access to Administrators only".

## 14. Licensing

`MIT`. The Python original was GPL-2.0-only **because** it imported and
redistributed `scapy`; that inheritance is gone because this implementation has
no packet-capture library dependency at all — the classifier, both capture-file
readers and the raw socket backend are written directly. Note that `dumpcap` is
*executed* as a separate process, never linked, so Wireshark's GPL does not
reach this code.

Ship `LICENSE`, `THIRD-PARTY-LICENSES.md` and `licenses/Apache-2.0.txt` with
any binary. Only the first is this project's license. The Apache text is a
third-party notice — `winit` and a handful of others are Apache-2.0 only, and
that license requires its text reach every recipient of the binary — and it is
kept under `licenses/` so that neither a reader nor GitHub's license detector
takes it for a second license on this code. `build.sh` copies all three into
`dist/` and fails if one is missing.

## 15. Testing

83 tests run under `cargo test --workspace`, and unlike the original there is
a real suite rather than manual eyeballing. Priorities, in order:

1. **`parse_frame` against hand-built byte sequences** — each EtherType,
   HSR/PRP/VLAN/QinQ combination, both APDU shapes, and malformed input. The
   truncation test slices a valid frame at *every* length and asserts no
   panic; BER length handling has several off-by-one edges around short
   buffers and this is what pins them down.
2. **Negative classification** — a matching port with wrong framing must stay
   `Ipv4`; mDNS/SSDP/IGMP must not become R-GOOSE. These guard the
   distinguishing design decision of the whole classifier.
3. **Capture-file readers** — round-trip pcap and pcapng, reject non-capture
   magic (including a gzip header), reject non-Ethernet link types, and end
   cleanly at every truncation point.
4. **Statistics and report** — rotation semantics, session totals surviving
   rotation, idle rows, subtotal-only-when-multiple, display filtering
   affecting totals.
5. **Rendering** — every panel line the same visible width, output entirely
   ASCII.

For end-to-end validation, run real captures through `--pcap` and compare
packet/byte totals against Wireshark, or against the Python original if it is
still available. On the reference captures the two agree exactly on packet and
byte counts (46,263 packets / 28.4 MB on a 31 MB pcapng), while the Rust
implementation loads it in 0.10 s against Python's 10.8 s — about 106×.

## 16. Deliberate differences from the Python original

Reproducing the Python behaviour in these five places would reproduce known
defects.

1. **R-GOOSE false positives (fixed).** The Python classified *any*
   `224.0.0.0/4` UDP frame as R-GOOSE or R-SV. On a real capture that swept
   mDNS, SSDP and IGMP into R-GOOSE. This implementation requires the payload
   to actually contain a session PDU, with a narrow address fallback (§5.8).
2. **R-SV was unreachable (fixed).** The Python documented a
   `224.0.1.x`/`224.0.2.x` split but read the *second* address octet, which is
   `0` for both, so the R-SV branch could never be taken. Payload-based
   detection removes the dependency on the address entirely.
3. **Wire length vs captured length.** Statistics now use `orig_len`, so a
   snaplen-truncated capture reports the load that was actually on the link.
4. **Non-Ethernet captures are rejected** rather than misparsed into
   plausible-looking nonsense.
5. **Table logic exists once.** The Python computed rows separately in the CLI
   and the GUI; they are now both consumers of `report::build_report`.

One behavioural note that is *not* a bug fix: `sim` is left empty when the
`0x61` goosePdu check fails (§5.5), where the Python's behaviour was
ambiguous. Reporting a simulation flag read from a header that turned out not
to precede a goosePdu would be asserting something unverified.

## 17. Suggested build order

1. `parse.rs` and its helpers — pure functions, unit-testable against
   hand-crafted bytes with no capture backend at all. Get GOOSE/SV/HSR/PRP/
   VLAN right first; it has the most spec detail and the highest cost of being
   subtly wrong.
2. `filter.rs` and `pcap.rs` — this lets you validate the classifier
   end-to-end against real `.pcapng` fixtures before writing any live-capture
   or UI code.
3. `stats.rs` and `report.rs` — the rolling-window model and the row builder.
4. `capture.rs` — the concurrency-sensitive part. Test at a realistic Sampled
   Values rate (thousands of packets/second) to confirm the batching design
   keeps up.
5. `nlm-cli`.
6. `nlm-gui`, consuming the same engine rather than duplicating any of it.
7. Cross-compilation last, once both front ends work natively.
