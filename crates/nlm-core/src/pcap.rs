//! Capture-file readers for classic pcap and pcapng.
//!
//! Both formats are decoded directly from bytes. Beyond being fast enough to
//! keep up with a live `dumpcap` pipe at Sampled Values rates, this removes
//! the need for a general-purpose capture library, which is what forced the
//! original Python port to be GPL.

use crate::filter::FrameFilter;
use crate::parse::parse_frame;
use crate::stats::{StatKey, StatsMap};
use std::fmt;
use std::fs::File;
use std::io::{self, BufReader, ErrorKind, Read};
use std::path::Path;

/// LINKTYPE_ETHERNET. The classifier starts at an Ethernet header, so any
/// other link type would be silently misparsed into nonsense rows.
const LINKTYPE_ETHERNET: u32 = 1;

/// Largest frame accepted from a file. Comfortably above any jumbo frame, and
/// low enough that a corrupt or hostile length field cannot drive a huge
/// allocation.
const MAX_FRAME_LEN: usize = 262_144;

const PCAP_MAGIC_LE_US: u32 = 0xa1b2_c3d4;
const PCAP_MAGIC_LE_NS: u32 = 0xa1b2_3c4d;
const PCAP_MAGIC_BE_US: u32 = 0xd4c3_b2a1;
const PCAP_MAGIC_BE_NS: u32 = 0x4d3c_b2a1;
const PCAPNG_SHB: u32 = 0x0a0d_0d0a;
const PCAPNG_BYTE_ORDER: u32 = 0x1a2b_3c4d;
const PCAPNG_IDB: u32 = 0x0000_0001;
const PCAPNG_PB: u32 = 0x0000_0002;
const PCAPNG_SPB: u32 = 0x0000_0003;
const PCAPNG_EPB: u32 = 0x0000_0006;

/// Largest pcapng block accepted, for the same reason as [`MAX_FRAME_LEN`].
const MAX_BLOCK_LEN: u32 = 16 * 1024 * 1024;

#[derive(Debug)]
pub enum PcapError {
    Io(io::Error),
    /// The file is not a capture file we accept.
    NotACapture,
    /// A capture file, but not of Ethernet frames.
    UnsupportedLinkType(u32),
    Malformed(&'static str),
}

impl fmt::Display for PcapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PcapError::Io(e) => write!(f, "{e}"),
            PcapError::NotACapture => f.write_str(
                "not a pcap/pcapng file (its header does not carry a capture-file magic number)",
            ),
            PcapError::UnsupportedLinkType(n) => write!(
                f,
                "unsupported link type {n}; only Ethernet (link type 1) captures can be classified"
            ),
            PcapError::Malformed(what) => write!(f, "malformed capture file: {what}"),
        }
    }
}

impl std::error::Error for PcapError {}

impl From<io::Error> for PcapError {
    fn from(e: io::Error) -> Self {
        PcapError::Io(e)
    }
}

/// Whether these first bytes are a capture-file header we accept.
///
/// This is a security control as much as a validation step. A general capture
/// library will transparently decompress a gzip-wrapped file with no size cap,
/// so a small crafted `.gz` renamed to `.pcap` could expand into an effectively
/// unbounded stream. Plain pcap and pcapng have no such amplification — bytes
/// read equal bytes on disk — so refusing everything else closes that door
/// without limiting legitimately large captures.
///
/// Always check the real header. Never trust a file extension or a file
/// picker's type filter.
pub fn is_capture_magic(head: &[u8]) -> bool {
    if head.len() < 4 {
        return false;
    }
    let le = u32::from_le_bytes([head[0], head[1], head[2], head[3]]);
    matches!(
        le,
        PCAP_MAGIC_LE_US | PCAP_MAGIC_LE_NS | PCAP_MAGIC_BE_US | PCAP_MAGIC_BE_NS
    ) || head[..4] == PCAPNG_SHB.to_be_bytes()
        || head[..4] == PCAPNG_SHB.to_le_bytes()
}

// =========================================================================
// Byte-order-aware reading
// =========================================================================

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Endian {
    Little,
    Big,
}

impl Endian {
    fn u16(&self, b: [u8; 2]) -> u16 {
        match self {
            Endian::Little => u16::from_le_bytes(b),
            Endian::Big => u16::from_be_bytes(b),
        }
    }

    fn u32(&self, b: [u8; 4]) -> u32 {
        match self {
            Endian::Little => u32::from_le_bytes(b),
            Endian::Big => u32::from_be_bytes(b),
        }
    }
}

/// A reader that remembers how many bytes it has consumed, so an offline load
/// can report progress against the file size.
struct Counting<R> {
    inner: R,
    pos: u64,
}

impl<R: Read> Read for Counting<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.pos += n as u64;
        Ok(n)
    }
}

/// Fill `buf` completely. Returns `false` on a clean EOF or a short read,
/// which both mean "the stream ended", not "something went wrong".
///
/// Reading in a loop is required rather than optional: on a pipe from
/// `dumpcap`, a single read can return a partial record header.
fn read_full(r: &mut impl Read, buf: &mut [u8]) -> io::Result<bool> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => return Ok(false),
            Ok(k) => n += k,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

fn skip(r: &mut impl Read, mut n: u64) -> io::Result<bool> {
    let mut scratch = [0u8; 4096];
    while n > 0 {
        let want = n.min(scratch.len() as u64) as usize;
        if !read_full(r, &mut scratch[..want])? {
            return Ok(false);
        }
        n -= want as u64;
    }
    Ok(true)
}

// =========================================================================
// Reader
// =========================================================================

/// A streaming source of Ethernet frames from a capture stream.
///
/// Frames are handed out one at a time into an internal buffer, so a whole
/// capture never has to be resident and a live pipe can be consumed
/// indefinitely.
pub struct CaptureReader<R: Read> {
    src: Counting<R>,
    format: Format,
    buf: Vec<u8>,
    /// Bytes captured and original wire length of the frame now in `buf`.
    len: usize,
    orig_len: u32,
    ts: f64,
}

enum Format {
    Pcap { endian: Endian, ts_div: f64 },
    /// pcapng carries per-interface timestamp resolution and link type.
    PcapNg { endian: Endian, ifaces: Vec<IfaceInfo> },
}

struct IfaceInfo {
    ts_div: f64,
    link_type: u32,
}

impl<R: Read> CaptureReader<R> {
    /// Read the stream header and prepare to yield frames.
    pub fn new(reader: R) -> Result<Self, PcapError> {
        let mut src = Counting { inner: reader, pos: 0 };
        let mut magic = [0u8; 4];
        if !read_full(&mut src, &mut magic)? {
            return Err(PcapError::NotACapture);
        }
        if !is_capture_magic(&magic) {
            return Err(PcapError::NotACapture);
        }

        let format = if magic == PCAPNG_SHB.to_be_bytes() || magic == PCAPNG_SHB.to_le_bytes() {
            Format::PcapNg { endian: Endian::Little, ifaces: Vec::new() }
        } else {
            let le = u32::from_le_bytes(magic);
            let (endian, ts_div) = match le {
                PCAP_MAGIC_LE_US => (Endian::Little, 1e6),
                PCAP_MAGIC_LE_NS => (Endian::Little, 1e9),
                PCAP_MAGIC_BE_US => (Endian::Big, 1e6),
                PCAP_MAGIC_BE_NS => (Endian::Big, 1e9),
                _ => return Err(PcapError::NotACapture),
            };
            // Remaining 20 bytes of the global header; only link type matters.
            let mut rest = [0u8; 20];
            if !read_full(&mut src, &mut rest)? {
                return Err(PcapError::Malformed("truncated pcap header"));
            }
            let link_type = endian.u32([rest[16], rest[17], rest[18], rest[19]]);
            if link_type != LINKTYPE_ETHERNET {
                return Err(PcapError::UnsupportedLinkType(link_type));
            }
            Format::Pcap { endian, ts_div }
        };

        let mut r = CaptureReader {
            src,
            format,
            buf: Vec::new(),
            len: 0,
            orig_len: 0,
            ts: 0.0,
        };
        // For pcapng the magic we consumed was the start of the first SHB;
        // finish reading it so the stream sits on a block boundary.
        if matches!(r.format, Format::PcapNg { .. }) {
            r.read_shb_remainder()?;
        }
        Ok(r)
    }

    /// Bytes consumed so far, for progress reporting.
    pub fn position(&self) -> u64 {
        self.src.pos
    }

    /// The next Ethernet frame, or `None` at end of stream.
    ///
    /// Returns the frame bytes together with its original on-the-wire length
    /// and timestamp in seconds.
    pub fn next_frame(&mut self) -> Result<Option<CapturedFrame<'_>>, PcapError> {
        loop {
            let got = match &self.format {
                Format::Pcap { .. } => self.next_pcap()?,
                Format::PcapNg { .. } => self.next_pcapng()?,
            };
            match got {
                Some(true) => {
                    return Ok(Some(CapturedFrame {
                        data: &self.buf[..self.len],
                        orig_len: self.orig_len,
                        ts: self.ts,
                    }))
                }
                // A block that carried no frame (interface description,
                // metadata, a non-Ethernet interface): keep going.
                Some(false) => continue,
                None => return Ok(None),
            }
        }
    }

    fn next_pcap(&mut self) -> Result<Option<bool>, PcapError> {
        let Format::Pcap { endian, ts_div } = self.format else {
            unreachable!()
        };
        let mut hdr = [0u8; 16];
        if !read_full(&mut self.src, &mut hdr)? {
            return Ok(None);
        }
        let ts_sec = endian.u32([hdr[0], hdr[1], hdr[2], hdr[3]]);
        let ts_frac = endian.u32([hdr[4], hdr[5], hdr[6], hdr[7]]);
        let incl_len = endian.u32([hdr[8], hdr[9], hdr[10], hdr[11]]) as usize;
        let orig_len = endian.u32([hdr[12], hdr[13], hdr[14], hdr[15]]);

        if incl_len > MAX_FRAME_LEN {
            return Err(PcapError::Malformed("record length exceeds the maximum frame size"));
        }
        self.buf.resize(incl_len.max(1), 0);
        if !read_full(&mut self.src, &mut self.buf[..incl_len])? {
            return Ok(None);
        }
        self.len = incl_len;
        self.orig_len = orig_len;
        self.ts = ts_sec as f64 + ts_frac as f64 / ts_div;
        Ok(Some(true))
    }

    /// Read the rest of a Section Header Block, whose type field is already
    /// consumed. Establishes the section's byte order and resets interfaces.
    fn read_shb_remainder(&mut self) -> Result<(), PcapError> {
        let mut head = [0u8; 8]; // block total length + byte-order magic
        if !read_full(&mut self.src, &mut head)? {
            return Err(PcapError::Malformed("truncated section header block"));
        }
        let bom = [head[4], head[5], head[6], head[7]];
        let endian = if u32::from_le_bytes(bom) == PCAPNG_BYTE_ORDER {
            Endian::Little
        } else if u32::from_be_bytes(bom) == PCAPNG_BYTE_ORDER {
            Endian::Big
        } else {
            return Err(PcapError::Malformed("bad pcapng byte-order magic"));
        };
        let total = endian.u32([head[0], head[1], head[2], head[3]]);
        if !(12..=MAX_BLOCK_LEN).contains(&total) {
            return Err(PcapError::Malformed("implausible section header block length"));
        }
        // Skip the rest of the SHB: version, section length, options, trailer.
        // 12 bytes already read (type, length, BOM).
        skip(&mut self.src, (total - 12) as u64)?;
        // A new section restarts interface numbering.
        self.format = Format::PcapNg { endian, ifaces: Vec::new() };
        Ok(())
    }

    /// Read one pcapng block. `Some(true)` when it yielded a frame.
    fn next_pcapng(&mut self) -> Result<Option<bool>, PcapError> {
        let Format::PcapNg { endian, .. } = &self.format else {
            unreachable!()
        };
        let endian = *endian;

        let mut btype = [0u8; 4];
        if !read_full(&mut self.src, &mut btype)? {
            return Ok(None);
        }
        let block_type = endian.u32(btype);
        if block_type == PCAPNG_SHB {
            self.read_shb_remainder()?;
            return Ok(Some(false));
        }

        let mut lenbuf = [0u8; 4];
        if !read_full(&mut self.src, &mut lenbuf)? {
            return Ok(None);
        }
        let total = endian.u32(lenbuf);
        if !(12..=MAX_BLOCK_LEN).contains(&total) {
            return Err(PcapError::Malformed("implausible block length"));
        }
        // Body sits between the 8-byte header and the 4-byte trailing length.
        let body_len = (total - 12) as usize;
        let mut body = vec![0u8; body_len];
        if !read_full(&mut self.src, &mut body)? {
            return Ok(None);
        }
        let mut trailer = [0u8; 4];
        if !read_full(&mut self.src, &mut trailer)? {
            return Ok(None);
        }

        match block_type {
            PCAPNG_IDB => {
                self.add_interface(endian, &body);
                Ok(Some(false))
            }
            PCAPNG_EPB => Ok(Some(self.take_epb(endian, &body))),
            PCAPNG_SPB => Ok(Some(self.take_spb(endian, &body))),
            PCAPNG_PB => Ok(Some(self.take_legacy_pb(endian, &body))),
            _ => Ok(Some(false)),
        }
    }

    fn add_interface(&mut self, endian: Endian, body: &[u8]) {
        if body.len() < 8 {
            return;
        }
        let link_type = endian.u16([body[0], body[1]]) as u32;
        // if_tsresol (option code 9) overrides the default of microseconds.
        let mut ts_div = 1e6;
        let mut off = 8;
        while off + 4 <= body.len() {
            let code = endian.u16([body[off], body[off + 1]]);
            let len = endian.u16([body[off + 2], body[off + 3]]) as usize;
            let val_start = off + 4;
            if code == 0 {
                break; // opt_endofopt
            }
            if val_start + len > body.len() {
                break;
            }
            if code == 9 && len >= 1 {
                let v = body[val_start];
                ts_div = if v & 0x80 != 0 {
                    2f64.powi((v & 0x7F) as i32)
                } else {
                    10f64.powi(v as i32)
                };
            }
            // Option values are padded to a 4-byte boundary.
            off = val_start + len.div_ceil(4) * 4;
        }
        if let Format::PcapNg { ifaces, .. } = &mut self.format {
            ifaces.push(IfaceInfo { ts_div, link_type });
        }
    }

    /// Whether frames from this interface should be classified at all.
    fn iface(&self, id: usize) -> Option<&IfaceInfo> {
        match &self.format {
            Format::PcapNg { ifaces, .. } => ifaces.get(id),
            _ => None,
        }
    }

    fn take_epb(&mut self, endian: Endian, body: &[u8]) -> bool {
        if body.len() < 20 {
            return false;
        }
        let iface_id = endian.u32([body[0], body[1], body[2], body[3]]) as usize;
        let ts_high = endian.u32([body[4], body[5], body[6], body[7]]) as u64;
        let ts_low = endian.u32([body[8], body[9], body[10], body[11]]) as u64;
        let cap_len = endian.u32([body[12], body[13], body[14], body[15]]) as usize;
        let orig_len = endian.u32([body[16], body[17], body[18], body[19]]);

        let Some(info) = self.iface(iface_id) else {
            return false;
        };
        if info.link_type != LINKTYPE_ETHERNET {
            return false;
        }
        let ts = ((ts_high << 32) | ts_low) as f64 / info.ts_div;
        if cap_len > MAX_FRAME_LEN || 20 + cap_len > body.len() {
            return false;
        }
        self.buf.clear();
        self.buf.extend_from_slice(&body[20..20 + cap_len]);
        self.len = cap_len;
        self.orig_len = orig_len;
        self.ts = ts;
        true
    }

    fn take_spb(&mut self, endian: Endian, body: &[u8]) -> bool {
        if body.len() < 4 {
            return false;
        }
        // A simple packet block has no interface id; it implies interface 0.
        match self.iface(0) {
            Some(info) if info.link_type == LINKTYPE_ETHERNET => {}
            _ => return false,
        }
        let orig_len = endian.u32([body[0], body[1], body[2], body[3]]);
        let cap_len = (body.len() - 4).min(orig_len as usize).min(MAX_FRAME_LEN);
        self.buf.clear();
        self.buf.extend_from_slice(&body[4..4 + cap_len]);
        self.len = cap_len;
        self.orig_len = orig_len;
        // Simple packet blocks carry no timestamp; reuse the previous one so
        // the capture's overall span stays monotonic.
        true
    }

    fn take_legacy_pb(&mut self, endian: Endian, body: &[u8]) -> bool {
        if body.len() < 20 {
            return false;
        }
        let iface_id = endian.u16([body[0], body[1]]) as usize;
        let ts_high = endian.u32([body[4], body[5], body[6], body[7]]) as u64;
        let ts_low = endian.u32([body[8], body[9], body[10], body[11]]) as u64;
        let cap_len = endian.u32([body[12], body[13], body[14], body[15]]) as usize;
        let orig_len = endian.u32([body[16], body[17], body[18], body[19]]);

        let Some(info) = self.iface(iface_id) else {
            return false;
        };
        if info.link_type != LINKTYPE_ETHERNET {
            return false;
        }
        let ts = ((ts_high << 32) | ts_low) as f64 / info.ts_div;
        if cap_len > MAX_FRAME_LEN || 20 + cap_len > body.len() {
            return false;
        }
        self.buf.clear();
        self.buf.extend_from_slice(&body[20..20 + cap_len]);
        self.len = cap_len;
        self.orig_len = orig_len;
        self.ts = ts;
        true
    }
}

/// One frame handed out by a [`CaptureReader`].
pub struct CapturedFrame<'a> {
    pub data: &'a [u8],
    /// Length on the wire, which may exceed `data.len()` under a snaplen.
    pub orig_len: u32,
    /// Capture timestamp in seconds.
    pub ts: f64,
}

// =========================================================================
// Offline loading
// =========================================================================

/// The outcome of reading a capture file.
#[derive(Debug)]
pub struct LoadResult {
    pub stats: StatsMap,
    /// Span between the first and last packet, standing in for a live window.
    pub duration_s: f64,
    pub packets: u64,
    pub bytes: u64,
}

/// Read a capture file and accumulate per-protocol statistics.
///
/// `progress` is called periodically with `(packets, bytes, percent)` and once
/// more at completion; percent tracks the reader's byte position in the file,
/// which is the only measure available before the packet count is known.
/// Returning `false` from it aborts the load, which is how the GUI cancels.
pub fn load_file(
    path: &Path,
    filter: &FrameFilter,
    progress: &mut dyn FnMut(u64, u64, f64) -> bool,
) -> Result<LoadResult, PcapError> {
    let file = File::open(path)?;
    let file_size = file.metadata().map(|m| m.len()).unwrap_or(0).max(1);

    // Validate before handing the file to any parser at all.
    let mut head = [0u8; 4];
    {
        let mut probe = &file;
        if !read_full(&mut probe, &mut head)? || !is_capture_magic(&head) {
            return Err(PcapError::NotACapture);
        }
    }
    let file = File::open(path)?;
    let mut reader = CaptureReader::new(BufReader::with_capacity(1 << 20, file))?;

    let mut stats = StatsMap::new();
    let mut packets = 0u64;
    let mut bytes = 0u64;
    let mut t_min = f64::INFINITY;
    let mut t_max = f64::NEG_INFINITY;
    let mut since_progress = 0u64;

    while let Some(frame) = reader.next_frame()? {
        let parsed = parse_frame(frame.data);
        let ts = frame.ts;
        // Wire length, not captured length: a snaplen-truncated frame still
        // occupied its full size on the link being measured.
        let size = frame.orig_len.max(frame.data.len() as u32) as u64;

        if ts > 0.0 {
            t_min = t_min.min(ts);
            t_max = t_max.max(ts);
        }

        if filter.matches(&parsed) {
            packets += 1;
            bytes += size;
            let entry = stats.entry(parsed.proto).or_default().entry(StatKey::from(&parsed)).or_default();
            entry.packets += 1;
            entry.bytes += size;
        }

        since_progress += 1;
        if since_progress >= crate::consts::PCAP_PROGRESS_EVERY {
            since_progress = 0;
            let pct = (reader.position() as f64 / file_size as f64 * 100.0).min(100.0);
            if !progress(packets, bytes, pct) {
                break;
            }
        }
    }

    progress(packets, bytes, 100.0);

    let duration_s = if t_max > t_min { (t_max - t_min).max(0.001) } else { 0.001 };
    Ok(LoadResult { stats, duration_s, packets, bytes })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::Protocol;

    /// A minimal PTP-over-Ethernet frame.
    fn ptp_frame() -> Vec<u8> {
        let mut v = vec![0xFFu8; 12];
        v.extend_from_slice(&[0x88, 0xF7]);
        v.extend_from_slice(&[0u8; 44]);
        v
    }

    fn build_pcap(frames: &[Vec<u8>], link_type: u32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&PCAP_MAGIC_LE_US.to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(&0i32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&65535u32.to_le_bytes());
        out.extend_from_slice(&link_type.to_le_bytes());
        for (i, f) in frames.iter().enumerate() {
            out.extend_from_slice(&(100 + i as u32).to_le_bytes()); // ts_sec
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&(f.len() as u32).to_le_bytes());
            out.extend_from_slice(&(f.len() as u32).to_le_bytes());
            out.extend_from_slice(f);
        }
        out
    }

    fn build_pcapng(frames: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        // Section Header Block.
        out.extend_from_slice(&PCAPNG_SHB.to_le_bytes());
        out.extend_from_slice(&28u32.to_le_bytes());
        out.extend_from_slice(&PCAPNG_BYTE_ORDER.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes()); // major
        out.extend_from_slice(&0u16.to_le_bytes()); // minor
        out.extend_from_slice(&(-1i64).to_le_bytes()); // section length
        out.extend_from_slice(&28u32.to_le_bytes());
        // Interface Description Block, Ethernet, default µs resolution.
        out.extend_from_slice(&PCAPNG_IDB.to_le_bytes());
        out.extend_from_slice(&20u32.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes()); // link type
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&65535u32.to_le_bytes());
        out.extend_from_slice(&20u32.to_le_bytes());
        // Enhanced Packet Blocks.
        for (i, f) in frames.iter().enumerate() {
            let pad = f.len().div_ceil(4) * 4;
            let total = 32 + pad as u32;
            out.extend_from_slice(&PCAPNG_EPB.to_le_bytes());
            out.extend_from_slice(&total.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes()); // interface id
            let ts = (100 + i as u64) * 1_000_000;
            out.extend_from_slice(&((ts >> 32) as u32).to_le_bytes());
            out.extend_from_slice(&(ts as u32).to_le_bytes());
            out.extend_from_slice(&(f.len() as u32).to_le_bytes());
            out.extend_from_slice(&(f.len() as u32).to_le_bytes());
            out.extend_from_slice(f);
            out.extend_from_slice(&vec![0u8; pad - f.len()]);
            out.extend_from_slice(&total.to_le_bytes());
        }
        out
    }

    fn read_all(bytes: &[u8]) -> Vec<Vec<u8>> {
        let mut r = CaptureReader::new(io::Cursor::new(bytes.to_vec())).unwrap();
        let mut out = Vec::new();
        while let Some(f) = r.next_frame().unwrap() {
            out.push(f.data.to_vec());
        }
        out
    }

    #[test]
    fn accepts_only_real_capture_magics() {
        assert!(is_capture_magic(&PCAP_MAGIC_LE_US.to_le_bytes()));
        assert!(is_capture_magic(&PCAP_MAGIC_LE_NS.to_le_bytes()));
        assert!(is_capture_magic(&PCAP_MAGIC_BE_US.to_le_bytes()));
        assert!(is_capture_magic(&PCAPNG_SHB.to_be_bytes()));
        // A gzip header is the case this check exists to reject.
        assert!(!is_capture_magic(&[0x1f, 0x8b, 0x08, 0x00]));
        assert!(!is_capture_magic(b"PK\x03\x04"));
        assert!(!is_capture_magic(&[0x00]));
    }

    #[test]
    fn reads_classic_pcap() {
        let frames = vec![ptp_frame(), ptp_frame()];
        let got = read_all(&build_pcap(&frames, LINKTYPE_ETHERNET));
        assert_eq!(got, frames);
    }

    #[test]
    fn reads_pcapng_with_enhanced_packet_blocks() {
        let frames = vec![ptp_frame(), ptp_frame(), ptp_frame()];
        let got = read_all(&build_pcapng(&frames));
        assert_eq!(got, frames);
    }

    #[test]
    fn rejects_non_ethernet_captures() {
        // Linux cooked capture (link type 113) would misparse as Ethernet.
        let err = CaptureReader::new(io::Cursor::new(build_pcap(&[ptp_frame()], 113)));
        assert!(matches!(err.err(), Some(PcapError::UnsupportedLinkType(113))));
    }

    #[test]
    fn rejects_non_capture_input() {
        let err = CaptureReader::new(io::Cursor::new(b"\x1f\x8b\x08\x00 gzip".to_vec()));
        assert!(matches!(err.err(), Some(PcapError::NotACapture)));
    }

    #[test]
    fn truncated_streams_end_cleanly() {
        let full = build_pcap(&[ptp_frame(), ptp_frame()], LINKTYPE_ETHERNET);
        // Cutting anywhere past the header must stop, never error or hang.
        for n in 24..full.len() {
            let mut r = CaptureReader::new(io::Cursor::new(full[..n].to_vec())).unwrap();
            while let Some(_f) = r.next_frame().unwrap() {}
        }
    }

    #[test]
    fn load_file_counts_and_times_a_capture() {
        let dir = std::env::temp_dir().join(format!("nlm-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sample.pcapng");
        let frames = vec![ptp_frame(), ptp_frame(), ptp_frame()];
        std::fs::write(&path, build_pcapng(&frames)).unwrap();

        let mut calls = 0;
        let res = load_file(&path, &FrameFilter::default(), &mut |_, _, _| {
            calls += 1;
            true
        })
        .unwrap();

        assert_eq!(res.packets, 3);
        assert_eq!(res.bytes, 3 * ptp_frame().len() as u64);
        // Timestamps one second apart across three packets.
        assert!((res.duration_s - 2.0).abs() < 1e-6);
        assert_eq!(res.stats[&Protocol::Ptp].values().map(|c| c.packets).sum::<u64>(), 3);
        assert!(calls >= 1, "progress must be reported at least once at completion");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_file_refuses_a_disguised_non_capture() {
        let dir = std::env::temp_dir().join(format!("nlm-test-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("evil.pcap");
        std::fs::write(&path, b"\x1f\x8b\x08\x00not really a capture").unwrap();

        let err = load_file(&path, &FrameFilter::default(), &mut |_, _, _| true);
        assert!(matches!(err.err(), Some(PcapError::NotACapture)));
        std::fs::remove_dir_all(&dir).ok();
    }
}
