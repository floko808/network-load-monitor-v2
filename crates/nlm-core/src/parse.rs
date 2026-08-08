//! Frame classification: raw Ethernet bytes in, protocol + framing metadata out.
//!
//! Everything here is hand-rolled over `&[u8]`. There is no packet-object
//! model and no ASN.1 library: at Sampled Values rates (thousands of frames
//! per second, per stream) the per-frame budget is well under a microsecond,
//! and every accessor below is bounds-checked so a truncated or hostile frame
//! can only ever produce a less-populated row, never a panic.

use crate::consts::*;
use std::fmt;

/// Maximum stacked VLAN tags recorded per frame. Two covers 802.1ad QinQ;
/// the extra headroom means unusual stacks are still counted rather than
/// silently truncated into a different-looking row.
pub const MAX_VLAN_TAGS: usize = 4;

/// Placeholder rendered for any column a frame has no value for.
pub const NONE_STR: &str = "-";

// =========================================================================
// Byte helpers
// =========================================================================

/// Big-endian u16 at `off`, or `None` if it would read past the end.
#[inline]
fn u16be(data: &[u8], off: usize) -> Option<u16> {
    let hi = *data.get(off)? as u16;
    let lo = *data.get(off + 1)? as u16;
    Some((hi << 8) | lo)
}

/// Big-endian unsigned integer over `bytes`, saturating at `u64::MAX`.
///
/// BER INTEGERs are variable-length and a corrupt frame can claim a very long
/// one; saturating keeps the value meaningless-but-harmless instead of
/// wrapping into a plausible-looking small number.
fn be_uint(bytes: &[u8]) -> u64 {
    let mut v: u64 = 0;
    for &b in bytes {
        match v.checked_shl(8) {
            Some(shifted) => v = shifted | b as u64,
            None => return u64::MAX,
        }
    }
    v
}

/// Decode a BER VisibleString, replacing anything non-printable.
///
/// These strings land in a terminal table and a GUI grid, so a frame carrying
/// control bytes must not be able to move the cursor or inject escapes.
fn ber_string(bytes: &[u8]) -> Box<str> {
    bytes
        .iter()
        .map(|&b| if (0x20..0x7F).contains(&b) { b as char } else { '.' })
        .collect::<String>()
        .into_boxed_str()
}

/// BER length octet(s) at `off`, returning `(length, bytes_consumed)`.
///
/// Short form (`< 0x80`) is the length itself; long form has the high bit set
/// with the low 7 bits giving the number of big-endian length bytes that
/// follow. A length too large for `usize` saturates — callers bound every
/// resulting offset against the buffer anyway, so a saturated value simply
/// fails that check.
fn ber_len(data: &[u8], off: usize) -> (usize, usize) {
    let Some(&b) = data.get(off) else {
        return (0, 0);
    };
    if b < 0x80 {
        return (b as usize, 1);
    }
    let n = (b & 0x7F) as usize;
    if off + 1 + n > data.len() {
        return (0, 1 + n);
    }
    let v = be_uint(&data[off + 1..off + 1 + n]);
    (usize::try_from(v).unwrap_or(usize::MAX), 1 + n)
}

/// One TLV read out of a BER walk.
struct Tlv {
    tag: u8,
    start: usize,
    end: usize,
}

/// Read the TLV at `off`, bounded by `end`. Returns `None` when the buffer is
/// exhausted or the element's own length runs past `end` (truncated frame).
fn read_tlv(data: &[u8], off: usize, end: usize) -> Option<Tlv> {
    if off + 1 >= end {
        return None;
    }
    let tag = data[off];
    let (len, consumed) = ber_len(data, off + 1);
    let start = off.checked_add(1)?.checked_add(consumed)?;
    let tlv_end = start.checked_add(len)?;
    if tlv_end > end {
        return None;
    }
    Some(Tlv { tag, start, end: tlv_end })
}

// =========================================================================
// Frame metadata types
// =========================================================================

/// The stacked 802.1Q/802.1ad tags found on a frame, outermost first.
///
/// Fixed-size and `Copy` so it can sit in a statistics key without allocating
/// per frame. Unused slots are always zero, which keeps the derived `Hash` and
/// `Eq` consistent with `len`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct VlanTags {
    len: u8,
    ids: [u16; MAX_VLAN_TAGS],
    pcps: [u8; MAX_VLAN_TAGS],
}

impl VlanTags {
    /// Append a tag. Tags past [`MAX_VLAN_TAGS`] are dropped.
    fn push(&mut self, id: u16, pcp: u8) {
        let i = self.len as usize;
        if i < MAX_VLAN_TAGS {
            self.ids[i] = id;
            self.pcps[i] = pcp;
            self.len = self.len.saturating_add(1);
        }
    }

    /// Build a tag stack directly, outermost first.
    pub fn from_tags(tags: &[(u16, u8)]) -> VlanTags {
        let mut v = VlanTags::default();
        for (id, pcp) in tags {
            v.push(*id, *pcp);
        }
        v
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// VLAN IDs, outermost first.
    pub fn ids(&self) -> &[u16] {
        &self.ids[..self.len as usize]
    }

    /// 802.1Q PCP (class of service) values, outermost first.
    pub fn pcps(&self) -> &[u8] {
        &self.pcps[..self.len as usize]
    }

    /// Comma-joined VLAN IDs for the VLAN column, or `-`.
    pub fn vlan_label(&self) -> String {
        join_or_dash(self.ids())
    }

    /// Comma-joined PCP values for the CoS column, or `-`.
    pub fn cos_label(&self) -> String {
        join_or_dash(self.pcps())
    }
}

fn join_or_dash<T: fmt::Display>(items: &[T]) -> String {
    if items.is_empty() {
        return NONE_STR.to_string();
    }
    let mut out = String::new();
    for (i, v) in items.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(&v.to_string());
    }
    out
}

/// IEC 62439-3 redundancy scheme and lane.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub enum Redundancy {
    #[default]
    None,
    /// HSR, carrying the 4-bit Path field.
    Hsr(u8),
    /// PRP, carrying the 4-bit LanId field.
    Prp(u8),
}

impl Redundancy {
    /// Lane letter for the conventional 0xA/0xB values, else the raw nibble.
    fn lane(nibble: u8) -> String {
        match nibble {
            0xA => "A".to_string(),
            0xB => "B".to_string(),
            n => format!("0x{n:X}"),
        }
    }
}

impl fmt::Display for Redundancy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Redundancy::None => f.write_str(NONE_STR),
            Redundancy::Hsr(p) => write!(f, "HSR-{}", Redundancy::lane(*p)),
            Redundancy::Prp(l) => write!(f, "PRP-{}", Redundancy::lane(*l)),
        }
    }
}

/// Every protocol the classifier can name.
///
/// Only the [`Protocol::is_featured`] variants can ever get their own detail
/// row; the rest exist so classification stays precise internally even though
/// they all render as `Other`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub enum Protocol {
    Goose,
    SampledValues,
    RGoose,
    Ptp,
    Mms,
    Dnp3,
    Iec104,
    ModbusTcp,
    // --- never broken out; always folded into "Other" ---
    RSv,
    Gsse,
    Ntp,
    Lldp,
    Rstp,
    Arp,
    Ipv4,
    Ipv6,
    Other,
}

impl Protocol {
    pub fn name(&self) -> &'static str {
        match self {
            Protocol::Goose => "GOOSE",
            Protocol::SampledValues => "Sampled Values",
            Protocol::RGoose => "R-GOOSE",
            Protocol::Ptp => "PTP",
            Protocol::Mms => "MMS",
            Protocol::Dnp3 => "DNP3",
            Protocol::Iec104 => "IEC104",
            Protocol::ModbusTcp => "Modbus TCP",
            Protocol::RSv => "R-SV",
            Protocol::Gsse => "GSSE",
            Protocol::Ntp => "NTP",
            Protocol::Lldp => "LLDP",
            Protocol::Rstp => "RSTP",
            Protocol::Arp => "ARP",
            Protocol::Ipv4 => "IPv4",
            Protocol::Ipv6 => "IPv6",
            Protocol::Other => "Other",
        }
    }

    /// Whether this protocol can be broken out of `Other` into its own rows.
    pub fn is_featured(&self) -> bool {
        PROTO_ORDER.contains(self)
    }

    /// The CLI flag / GUI checkbox name that enables this protocol's detail.
    pub fn flag(&self) -> Option<&'static str> {
        Some(match self {
            Protocol::Goose => "goose",
            Protocol::SampledValues => "sv",
            Protocol::RGoose => "rgoose",
            Protocol::Ptp => "ptp",
            Protocol::Mms => "mms",
            Protocol::Dnp3 => "dnp3",
            Protocol::Iec104 => "iec104",
            Protocol::ModbusTcp => "modbus",
            _ => return None,
        })
    }

    /// Resolve a flag name (as accepted on the CLI) back to a protocol.
    pub fn from_flag(s: &str) -> Option<Protocol> {
        PROTO_ORDER.iter().copied().find(|p| p.flag() == Some(s))
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Protocols eligible for a detail row, in fixed display order.
pub const PROTO_ORDER: [Protocol; 8] = [
    Protocol::Goose,
    Protocol::SampledValues,
    Protocol::RGoose,
    Protocol::Ptp,
    Protocol::Mms,
    Protocol::Dnp3,
    Protocol::Iec104,
    Protocol::ModbusTcp,
];

/// Application-layer header fields, populated only for GOOSE / SV / R-GOOSE.
///
/// `svid` doubles as the SVID (Sampled Values) or goID/gocbRef (GOOSE), and
/// `noasdu` as noASDU (SV) or stNum (GOOSE) — a frame is only ever one of the
/// two, so they share a column.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Default)]
pub struct AppInfo {
    pub appid: Option<u16>,
    pub svid: Option<Box<str>>,
    pub noasdu: Option<u64>,
    pub confrev: Option<u64>,
    pub sim: Option<bool>,
}

impl AppInfo {
    pub fn appid_label(&self) -> String {
        match self.appid {
            Some(v) => format!("0x{v:04X}"),
            None => NONE_STR.to_string(),
        }
    }

    pub fn svid_label(&self) -> String {
        match &self.svid {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => NONE_STR.to_string(),
        }
    }

    pub fn noasdu_label(&self) -> String {
        opt_num(self.noasdu)
    }

    pub fn confrev_label(&self) -> String {
        opt_num(self.confrev)
    }

    pub fn sim_label(&self) -> String {
        match self.sim {
            Some(true) => "yes".to_string(),
            Some(false) => "no".to_string(),
            None => NONE_STR.to_string(),
        }
    }

    pub fn is_sim(&self) -> bool {
        self.sim == Some(true)
    }
}

fn opt_num(v: Option<u64>) -> String {
    match v {
        Some(n) => n.to_string(),
        None => NONE_STR.to_string(),
    }
}

/// A fully classified frame.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Frame {
    pub proto: Protocol,
    pub vlans: VlanTags,
    pub redundancy: Redundancy,
    pub app: AppInfo,
}

impl Default for Frame {
    fn default() -> Self {
        Frame {
            proto: Protocol::Other,
            vlans: VlanTags::default(),
            redundancy: Redundancy::None,
            app: AppInfo::default(),
        }
    }
}

// =========================================================================
// The classifier
// =========================================================================

/// Classify one raw Ethernet frame.
///
/// Never fails: anything unrecognised, truncated or malformed classifies as
/// [`Protocol::Other`] with whatever framing metadata was readable.
pub fn parse_frame(data: &[u8]) -> Frame {
    let mut frame = Frame::default();

    // Below a full Ethernet header there is nothing to classify.
    if data.len() < 14 {
        return frame;
    }

    let mut off = 12;
    let Some(mut etype) = u16be(data, off) else {
        return frame;
    };
    off += 2;

    // --- 802.1Q / 802.1ad tags. Looping is what makes QinQ work. ---------
    while (etype == ET_VLAN || etype == ET_QINQ) && off + 4 <= data.len() {
        let tci_hi = data[off];
        let pcp = (tci_hi >> 5) & 0x07;
        let vlan_id = (((tci_hi & 0x0F) as u16) << 8) | data[off + 1] as u16;
        frame.vlans.push(vlan_id, pcp);
        match u16be(data, off + 2) {
            Some(inner) => etype = inner,
            None => return frame,
        }
        off += 4;
    }

    // --- HSR in-frame tag (IEC 62439-3 clause 5) ------------------------
    // 2 bytes Path/LSDUsize, 2 bytes SeqNr, 2 bytes embedded EtherType.
    if etype == ET_HSR && off + 6 <= data.len() {
        let path = (data[off] >> 4) & 0x0F;
        frame.redundancy = Redundancy::Hsr(path);
        match u16be(data, off + 4) {
            Some(inner) => etype = inner,
            None => return frame,
        }
        off += 6;
    }

    // --- PRP Redundancy Control Trailer (IEC 62439-3 clause 4) ----------
    // A 6-byte trailer at the *end* of the frame rather than an inline tag,
    // so it neither consumes offset nor changes the payload EtherType.
    if frame.redundancy == Redundancy::None && data.len() >= 6 {
        let n = data.len();
        if u16be(data, n - 2) == Some(PRP_SUF) {
            let lan_id = (data[n - 4] >> 4) & 0x0F;
            frame.redundancy = Redundancy::Prp(lan_id);
        }
    }

    // --- Payload classification by the resolved EtherType ----------------
    match etype {
        ET_GOOSE => {
            frame.proto = Protocol::Goose;
            frame.app = parse_goose_payload(data, off);
        }
        ET_SV => {
            frame.proto = Protocol::SampledValues;
            frame.app = parse_sv_payload(data, off);
        }
        ET_GSSE => frame.proto = Protocol::Gsse,
        ET_PTP => frame.proto = Protocol::Ptp,
        ET_LLDP => frame.proto = Protocol::Lldp,
        ET_ARP => frame.proto = Protocol::Arp,
        ET_IPV4 => {
            let (proto, app_off) = classify_ipv4(data, off);
            frame.proto = proto;
            if proto == Protocol::RGoose {
                if let Some(a) = app_off {
                    frame.app = parse_rgoose_payload(data, a);
                }
            }
        }
        ET_IPV6 => frame.proto = Protocol::Ipv6,
        // Values at or below 1500 are an IEEE 802.3 length field, not an
        // EtherType. DSAP == SSAP == 0x42 is the LLC SAP for STP/RSTP/MSTP.
        n if n <= 1500 => {
            frame.proto = if data.get(off) == Some(&0x42) && data.get(off + 1) == Some(&0x42) {
                Protocol::Rstp
            } else {
                Protocol::Other
            };
        }
        _ => frame.proto = Protocol::Other,
    }

    frame
}

// =========================================================================
// GOOSE / SV / R-GOOSE application headers
// =========================================================================

/// GOOSE APDU (IEC 61850-8-1 annex A).
///
/// 8-byte header — AppID, Length, Reserved1, Reserved2 — where the top bit of
/// Reserved1 is the simulation flag, followed by a `goosePdu` under BER tag
/// `0x61` (APPLICATION 1).
fn parse_goose_payload(data: &[u8], off: usize) -> AppInfo {
    let mut info = AppInfo::default();
    let Some(appid) = u16be(data, off) else {
        return info;
    };
    if off + 8 > data.len() {
        return info;
    }
    info.appid = Some(appid);
    let sim = data[off + 4] & 0x80 != 0;

    let p = off + 8;
    if data.get(p) != Some(&0x61) {
        // Not a goosePdu after all — keep the AppID we could read and leave
        // every decoded field empty rather than reporting guesses.
        return info;
    }
    info.sim = Some(sim);

    let (pdu_len, consumed) = ber_len(data, p + 1);
    let body = p + 1 + consumed;
    let end = body.saturating_add(pdu_len).min(data.len());

    let mut gocb_ref: Option<Box<str>> = None;
    let mut go_id: Option<Box<str>> = None;
    let mut cur = body;
    while let Some(tlv) = read_tlv(data, cur, end) {
        let val = &data[tlv.start..tlv.end];
        match tlv.tag {
            0x80 => gocb_ref = Some(ber_string(val)), // gocbRef  [0] VisibleString
            0x83 => go_id = Some(ber_string(val)),    // goID     [3] VisibleString
            0x85 => info.noasdu = Some(be_uint(val)), // stNum    [5] INTEGER
            0x88 => info.confrev = Some(be_uint(val)), // confRev [8] INTEGER
            _ => {}
        }
        if tlv.end <= cur {
            break; // zero-length element with no progress; stop rather than spin
        }
        cur = tlv.end;
    }
    // goID is the operator-facing name; gocbRef is the fallback when absent.
    info.svid = go_id.or(gocb_ref);
    info
}

/// Sampled Values APDU (IEC 61850-9-2).
///
/// Same 8-byte header shape as GOOSE, then a `savPdu` under BER tag `0x60`
/// (APPLICATION 0). Only the first ASDU is decoded — single-ASDU is
/// overwhelmingly the field case, and a multi-ASDU stream shares its svID and
/// confRev across ASDUs anyway.
fn parse_sv_payload(data: &[u8], off: usize) -> AppInfo {
    let mut info = AppInfo::default();
    let Some(appid) = u16be(data, off) else {
        return info;
    };
    if off + 8 > data.len() {
        return info;
    }
    info.appid = Some(appid);
    let sim = data[off + 4] & 0x80 != 0;

    let p = off + 8;
    if data.get(p) != Some(&0x60) {
        return info;
    }
    info.sim = Some(sim);

    let (pdu_len, consumed) = ber_len(data, p + 1);
    let body = p + 1 + consumed;
    let end = body.saturating_add(pdu_len).min(data.len());

    let mut cur = body;
    while let Some(tlv) = read_tlv(data, cur, end) {
        match tlv.tag {
            // noASDU [0] IMPLICIT INTEGER
            0x80 => info.noasdu = Some(be_uint(&data[tlv.start..tlv.end])),
            // seqOfAsdu [2] -> SEQUENCE (0x30) -> first ASDU
            0xA2 if data.get(tlv.start) == Some(&0x30) => {
                if let Some(asdu) = read_tlv(data, tlv.start, tlv.end) {
                    parse_sv_asdu(data, asdu.start, asdu.end, &mut info);
                }
            }
            _ => {}
        }
        if tlv.end <= cur {
            break;
        }
        cur = tlv.end;
    }
    info
}

/// Walk one ASDU for svID `[0]` and confRev `[3]`.
fn parse_sv_asdu(data: &[u8], start: usize, end: usize, info: &mut AppInfo) {
    let mut cur = start;
    while let Some(tlv) = read_tlv(data, cur, end) {
        let val = &data[tlv.start..tlv.end];
        match tlv.tag {
            0x80 => info.svid = Some(ber_string(val)),  // svID    [0] VisibleString
            0x83 => info.confrev = Some(be_uint(val)),  // confRev [3] INTEGER
            _ => {}
        }
        if tlv.end <= cur {
            break;
        }
        cur = tlv.end;
    }
}

/// R-GOOSE (routable GOOSE, IEC 61850-8-2) inside a UDP payload.
///
/// The `goosePdu` sits behind a Session PDU header whose length varies between
/// vendors, so rather than trusting a fixed offset this scans a bounded window
/// for the `0x61` tag. A candidate is accepted only when its BER length is
/// plausible *and* the next byte is `0x80` — the gocbRef tag that always opens
/// a goosePdu body — which rejects incidental `0x61` bytes in the session
/// header.
fn parse_rgoose_payload(data: &[u8], udp_off: usize) -> AppInfo {
    let mut info = AppInfo::default();
    let Some((tag_off, body, end)) = find_session_pdu(data, udp_off, GOOSE_PDU_TAG) else {
        return info;
    };

    // The 4-byte R-GOOSE APDU header (AppID + Length) immediately precedes
    // the PDU. Unlike L2 GOOSE there is no Reserved1 field, so the simulation
    // flag arrives as tag 0x87 inside the PDU instead.
    if tag_off >= 4 {
        info.appid = u16be(data, tag_off - 4);
    }

    let mut gocb_ref: Option<Box<str>> = None;
    let mut go_id: Option<Box<str>> = None;
    let mut sim = false;
    let mut cur = body;
    while let Some(tlv) = read_tlv(data, cur, end) {
        let val = &data[tlv.start..tlv.end];
        match tlv.tag {
            0x80 => gocb_ref = Some(ber_string(val)),
            0x83 => go_id = Some(ber_string(val)),
            0x85 => info.noasdu = Some(be_uint(val)),
            0x87 => sim = val.iter().any(|&b| b != 0), // simulation [7] BOOLEAN
            0x88 => info.confrev = Some(be_uint(val)),
            _ => {}
        }
        if tlv.end <= cur {
            break;
        }
        cur = tlv.end;
    }
    info.svid = go_id.or(gocb_ref);
    info.sim = Some(sim);
    info
}

/// BER tag of a `goosePdu` (APPLICATION 1).
const GOOSE_PDU_TAG: u8 = 0x61;
/// BER tag of a `savPdu` (APPLICATION 0).
const SV_PDU_TAG: u8 = 0x60;
/// How far into a UDP payload to look for the application PDU. Session
/// headers run to a few tens of bytes; this is generous without letting the
/// scan wander into payload data.
const SESSION_SCAN_WINDOW: usize = 128;

/// Locate an application PDU of `tag` inside a session-wrapped UDP payload.
///
/// Returns `(tag offset, body offset, body end)`. A candidate is accepted only
/// when its BER length is plausible *and* the next byte opens the body with
/// tag `0x80`, which rejects incidental tag bytes in the session header.
fn find_session_pdu(data: &[u8], udp_off: usize, tag: u8) -> Option<(usize, usize, usize)> {
    let start = udp_off.saturating_add(4);
    let stop = udp_off.saturating_add(SESSION_SCAN_WINDOW).min(data.len());
    for p in start..stop {
        if data[p] != tag {
            continue;
        }
        let (pdu_len, consumed) = ber_len(data, p + 1);
        if pdu_len == 0 || pdu_len >= 0x8000 {
            continue;
        }
        let body = p + 1 + consumed;
        if data.get(body) != Some(&0x80) {
            continue;
        }
        let end = body.saturating_add(pdu_len).min(data.len());
        return Some((p, body, end));
    }
    None
}

// =========================================================================
// IPv4 and the unicast SCADA protocols
// =========================================================================

/// Classify an IPv4 packet, returning the protocol and — for R-GOOSE/R-SV —
/// the offset of the UDP payload so the caller can decode the APDU.
fn classify_ipv4(data: &[u8], ip_off: usize) -> (Protocol, Option<usize>) {
    if ip_off + 20 > data.len() {
        return (Protocol::Ipv4, None);
    }

    // Non-first fragments carry no transport header, so there is nothing to
    // match a port against.
    let frag_off = (((data[ip_off + 6] & 0x1F) as u16) << 8) | data[ip_off + 7] as u16;
    if frag_off != 0 {
        return (Protocol::Ipv4, None);
    }

    let ip_proto = data[ip_off + 9];
    let ihl = (data[ip_off] & 0x0F) as usize * 4;
    let t_off = ip_off + ihl;
    let dst1 = data[ip_off + 16];

    match ip_proto {
        IPPROTO_TCP if t_off + 4 <= data.len() => {
            let (sport, dport) = match (u16be(data, t_off), u16be(data, t_off + 2)) {
                (Some(s), Some(d)) => (s, d),
                _ => return (Protocol::Ipv4, None),
            };
            // TCP data offset is in 32-bit words and must cover the fixed header.
            let payload: &[u8] = match data.get(t_off + 12) {
                Some(&b) => {
                    let doff = ((b >> 4) & 0x0F) as usize;
                    if doff >= 5 {
                        data.get(t_off + doff * 4..).unwrap_or(&[])
                    } else {
                        &[]
                    }
                }
                None => &[],
            };

            // A well-known port is only a hint. Each protocol must also match
            // its own framing signature, otherwise the frame stays plain IPv4
            // rather than being mislabelled by port number alone.
            let hit = |port: u16| sport == port || dport == port;
            if hit(PORT_MMS) && looks_like_mms(payload) {
                return (Protocol::Mms, None);
            }
            if hit(PORT_IEC104) && looks_like_iec104(payload) {
                return (Protocol::Iec104, None);
            }
            if hit(PORT_MODBUS) && looks_like_modbus(payload) {
                return (Protocol::ModbusTcp, None);
            }
            if hit(PORT_DNP3) && looks_like_dnp3(payload) {
                return (Protocol::Dnp3, None);
            }
            (Protocol::Ipv4, None)
        }

        IPPROTO_UDP if t_off + 4 <= data.len() => {
            let (sport, dport) = match (u16be(data, t_off), u16be(data, t_off + 2)) {
                (Some(s), Some(d)) => (s, d),
                _ => return (Protocol::Ipv4, None),
            };
            let hit = |port: u16| sport == port || dport == port;
            if hit(PORT_NTP) {
                return (Protocol::Ntp, None);
            }
            let udp_payload_off = t_off + 8;
            if hit(PORT_DNP3) && looks_like_dnp3(data.get(udp_payload_off..).unwrap_or(&[])) {
                return (Protocol::Dnp3, None);
            }
            // 224.0.0.0/4 — IEC 61850-8-2/9-3 run over UDP multicast.
            //
            // Membership of that range is nowhere near sufficient on its own:
            // it also covers mDNS (224.0.0.251), SSDP (239.255.255.250), IGMP
            // and every other ordinary IP multicast, all of which the Python
            // original counted as R-GOOSE. Confirm the payload actually
            // carries a session PDU first, exactly as the unicast protocols
            // above must match their own framing before their port is
            // trusted.
            if dst1 & 0xF0 == 0xE0 {
                if find_session_pdu(data, udp_payload_off, GOOSE_PDU_TAG).is_some() {
                    return (Protocol::RGoose, Some(udp_payload_off));
                }
                if find_session_pdu(data, udp_payload_off, SV_PDU_TAG).is_some() {
                    return (Protocol::RSv, None);
                }
                // Fall back to the conventional IEC allocation for a session
                // header longer than the scan window. Deliberately narrow:
                // only 224.0.1.0/24 and 224.0.2.0/24, which no general-purpose
                // multicast protocol uses.
                let (b1, b2) = (data[ip_off + 17], data[ip_off + 18]);
                if dst1 == 224 && b1 == 0 {
                    match b2 {
                        1 => return (Protocol::RGoose, Some(udp_payload_off)),
                        2 => return (Protocol::RSv, None),
                        _ => {}
                    }
                }
            }
            (Protocol::Ipv4, None)
        }

        _ => (Protocol::Ipv4, None),
    }
}

/// TPKT header (RFC 1006), which carries ISO/COTP and hence MMS.
fn looks_like_mms(payload: &[u8]) -> bool {
    payload.len() >= 4
        && payload[0] == 0x03
        && payload[1] == 0x00
        && u16be(payload, 2).is_some_and(|n| n >= 4)
}

/// IEC 60870-5-104 APCI: start byte 0x68 then a bounded length.
fn looks_like_iec104(payload: &[u8]) -> bool {
    payload.len() >= 2 && payload[0] == 0x68 && (4..=253).contains(&payload[1])
}

/// Modbus MBAP header: zero protocol id, bounded length, non-zero function.
fn looks_like_modbus(payload: &[u8]) -> bool {
    if payload.len() < 8 {
        return false;
    }
    let protocol_id = u16be(payload, 2).unwrap_or(1);
    let length = u16be(payload, 4).unwrap_or(0);
    let func_code = payload[7];
    protocol_id == 0 && (2..=253).contains(&length) && func_code != 0
}

/// DNP3 data-link layer start bytes 0x05 0x64 then a valid length.
fn looks_like_dnp3(payload: &[u8]) -> bool {
    payload.len() >= 3 && payload[0] == 0x05 && payload[1] == 0x64 && payload[2] >= 5
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an Ethernet frame: dst/src MAC, then `rest` from offset 12.
    fn eth(rest: &[u8]) -> Vec<u8> {
        let mut v = vec![0xFF; 12];
        v.extend_from_slice(rest);
        v
    }

    #[test]
    fn rejects_runt_frames() {
        assert_eq!(parse_frame(&[]).proto, Protocol::Other);
        assert_eq!(parse_frame(&[0u8; 13]).proto, Protocol::Other);
        // Truncation must never panic, at any length.
        let full = eth(&[0x88, 0xB8, 0x40, 0x41, 0x00, 0x10, 0x80, 0x00, 0x00, 0x00, 0x61, 0x03,
                         0x80, 0x01, 0x41]);
        for n in 0..full.len() {
            let _ = parse_frame(&full[..n]);
        }
    }

    #[test]
    fn classifies_plain_ethertypes() {
        assert_eq!(parse_frame(&eth(&[0x88, 0xF7, 0x00])).proto, Protocol::Ptp);
        assert_eq!(parse_frame(&eth(&[0x88, 0xCC, 0x00])).proto, Protocol::Lldp);
        assert_eq!(parse_frame(&eth(&[0x08, 0x06, 0x00])).proto, Protocol::Arp);
        assert_eq!(parse_frame(&eth(&[0x86, 0xDD, 0x00])).proto, Protocol::Ipv6);
        assert_eq!(parse_frame(&eth(&[0x88, 0xB9, 0x00])).proto, Protocol::Gsse);
        assert_eq!(parse_frame(&eth(&[0x99, 0x99, 0x00])).proto, Protocol::Other);
    }

    #[test]
    fn detects_llc_bpdu_as_rstp() {
        // 802.3 length field (<= 1500) followed by DSAP/SSAP 0x42.
        assert_eq!(parse_frame(&eth(&[0x00, 0x26, 0x42, 0x42, 0x03])).proto, Protocol::Rstp);
        assert_eq!(parse_frame(&eth(&[0x00, 0x26, 0xAA, 0xAA, 0x03])).proto, Protocol::Other);
    }

    #[test]
    fn unwraps_single_and_stacked_vlan_tags() {
        // One 802.1Q tag: PCP 4, VLAN 11, inner PTP.
        let f = parse_frame(&eth(&[0x81, 0x00, 0x80, 0x0B, 0x88, 0xF7, 0x00]));
        assert_eq!(f.proto, Protocol::Ptp);
        assert_eq!(f.vlans.ids(), &[11]);
        assert_eq!(f.vlans.pcps(), &[4]);
        assert_eq!(f.vlans.vlan_label(), "11");
        assert_eq!(f.vlans.cos_label(), "4");

        // QinQ: outer 802.1ad VLAN 100 PCP 2, inner 802.1Q VLAN 11 PCP 4.
        let f = parse_frame(&eth(&[
            0x88, 0xA8, 0x40, 0x64, 0x81, 0x00, 0x80, 0x0B, 0x88, 0xF7, 0x00,
        ]));
        assert_eq!(f.proto, Protocol::Ptp);
        assert_eq!(f.vlans.ids(), &[100, 11]);
        assert_eq!(f.vlans.vlan_label(), "100, 11");
        assert_eq!(f.vlans.cos_label(), "2, 4");
    }

    #[test]
    fn detects_hsr_tag_and_inner_protocol() {
        // HSR: Path 0xA, LSDUsize, SeqNr, then inner GOOSE EtherType.
        let f = parse_frame(&eth(&[0x89, 0x2F, 0xA0, 0x20, 0x00, 0x01, 0x88, 0xB8, 0x00, 0x00]));
        assert_eq!(f.proto, Protocol::Goose);
        assert_eq!(f.redundancy, Redundancy::Hsr(0xA));
        assert_eq!(f.redundancy.to_string(), "HSR-A");

        let f = parse_frame(&eth(&[0x89, 0x2F, 0xB0, 0x20, 0x00, 0x01, 0x88, 0xF7, 0x00, 0x00]));
        assert_eq!(f.redundancy.to_string(), "HSR-B");
        // An unconventional Path nibble still reports rather than being dropped.
        let f = parse_frame(&eth(&[0x89, 0x2F, 0x30, 0x20, 0x00, 0x01, 0x88, 0xF7, 0x00, 0x00]));
        assert_eq!(f.redundancy.to_string(), "HSR-0x3");
    }

    #[test]
    fn detects_prp_trailer_without_consuming_payload() {
        // PTP payload followed by a PRP RCT: SeqNr, LanId 0xB + LSDUsize, 0x88FB.
        let f = parse_frame(&eth(&[
            0x88, 0xF7, 0xAA, 0xBB, 0x00, 0x01, 0xB0, 0x10, 0x88, 0xFB,
        ]));
        assert_eq!(f.proto, Protocol::Ptp);
        assert_eq!(f.redundancy, Redundancy::Prp(0xB));
        assert_eq!(f.redundancy.to_string(), "PRP-B");
    }

    #[test]
    fn hsr_takes_precedence_over_a_trailing_prp_suffix() {
        let f = parse_frame(&eth(&[
            0x89, 0x2F, 0xA0, 0x20, 0x00, 0x01, 0x88, 0xF7, 0x00, 0x00, 0x00, 0x00, 0x88, 0xFB,
        ]));
        assert_eq!(f.redundancy, Redundancy::Hsr(0xA));
    }

    #[test]
    fn parses_goose_apdu() {
        // AppID 0x4041, Length, Res1 with sim bit set, Res2, then goosePdu.
        let goose_pdu = [
            0x61, 0x1C, // APPLICATION 1, len 28
            0x80, 0x0A, b'g', b'o', b'c', b'b', b'R', b'e', b'f', b'/', b'L', b'N', // gocbRef
            0x83, 0x06, b'm', b'y', b'G', b'O', b'0', b'1', // goID
            0x85, 0x02, 0x01, 0x2C, // stNum = 300
            0x88, 0x01, 0x07, // confRev = 7
        ];
        let mut payload = vec![0x88, 0xB8, 0x40, 0x41, 0x00, 0x20, 0x80, 0x00, 0x00, 0x00];
        payload.extend_from_slice(&goose_pdu);
        let f = parse_frame(&eth(&payload));

        assert_eq!(f.proto, Protocol::Goose);
        assert_eq!(f.app.appid, Some(0x4041));
        assert_eq!(f.app.appid_label(), "0x4041");
        assert_eq!(f.app.svid_label(), "myGO01"); // goID wins over gocbRef
        assert_eq!(f.app.noasdu, Some(300));
        assert_eq!(f.app.confrev, Some(7));
        assert_eq!(f.app.sim, Some(true));
    }

    #[test]
    fn goose_falls_back_to_gocbref_when_goid_absent() {
        let pdu = [0x61, 0x08, 0x80, 0x06, b'g', b'c', b'b', b'R', b'e', b'f'];
        let mut payload = vec![0x88, 0xB8, 0x40, 0x41, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00];
        payload.extend_from_slice(&pdu);
        let f = parse_frame(&eth(&payload));
        assert_eq!(f.app.svid_label(), "gcbRef");
        assert_eq!(f.app.sim, Some(false));
    }

    #[test]
    fn goose_without_pdu_tag_keeps_only_appid() {
        let payload = vec![0x88, 0xB8, 0x40, 0x41, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x99, 0x00];
        let f = parse_frame(&eth(&payload));
        assert_eq!(f.app.appid, Some(0x4041));
        assert_eq!(f.app.svid_label(), NONE_STR);
        assert_eq!(f.app.sim_label(), NONE_STR);
    }

    #[test]
    fn parses_sampled_values_apdu() {
        let asdu = [
            0x30, 0x0D, // ASDU SEQUENCE
            0x80, 0x08, b'M', b'U', b'0', b'1', b'_', b'S', b'V', b'1', // svID
            0x83, 0x01, 0x01, // confRev = 1
        ];
        let mut sav = vec![0xA2, asdu.len() as u8];
        sav.extend_from_slice(&asdu);
        let mut pdu = vec![0x80, 0x01, 0x02]; // noASDU = 2
        pdu.extend_from_slice(&sav);

        let mut payload = vec![0x88, 0xBA, 0x40, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00];
        payload.push(0x60);
        payload.push(pdu.len() as u8);
        payload.extend_from_slice(&pdu);

        let f = parse_frame(&eth(&payload));
        assert_eq!(f.proto, Protocol::SampledValues);
        assert_eq!(f.app.appid, Some(0x4000));
        assert_eq!(f.app.svid_label(), "MU01_SV1");
        assert_eq!(f.app.noasdu, Some(2));
        assert_eq!(f.app.confrev, Some(1));
        assert_eq!(f.app.sim, Some(false));
    }

    /// Build an IPv4 packet body starting at the Ethernet payload offset.
    fn ipv4(proto: u8, dst: [u8; 4], transport: &[u8]) -> Vec<u8> {
        let mut v = vec![0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, proto, 0x00, 0x00];
        v.extend_from_slice(&[10, 0, 0, 1]); // src
        v.extend_from_slice(&dst);
        v.extend_from_slice(transport);
        v
    }

    fn tcp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&sport.to_be_bytes());
        v.extend_from_slice(&dport.to_be_bytes());
        v.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]); // seq + ack
        v.extend_from_slice(&[0x50, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // doff=5
        v.extend_from_slice(payload);
        v
    }

    fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&sport.to_be_bytes());
        v.extend_from_slice(&dport.to_be_bytes());
        v.extend_from_slice(&[0, 0, 0, 0]);
        v.extend_from_slice(payload);
        v
    }

    fn ipv4_frame(body: Vec<u8>) -> Vec<u8> {
        let mut p = vec![0x08, 0x00];
        p.extend_from_slice(&body);
        eth(&p)
    }

    #[test]
    fn confirms_unicast_scada_protocols_by_signature() {
        let mms = ipv4_frame(ipv4(IPPROTO_TCP, [10, 0, 0, 2], &tcp(50000, 102, &[0x03, 0x00, 0x00, 0x16])));
        assert_eq!(parse_frame(&mms).proto, Protocol::Mms);

        let iec104 = ipv4_frame(ipv4(IPPROTO_TCP, [10, 0, 0, 2], &tcp(50000, 2404, &[0x68, 0x04, 0x07, 0x00])));
        assert_eq!(parse_frame(&iec104).proto, Protocol::Iec104);

        let modbus = ipv4_frame(ipv4(IPPROTO_TCP, [10, 0, 0, 2], &tcp(50000, 502, &[0, 1, 0, 0, 0, 6, 1, 3])));
        assert_eq!(parse_frame(&modbus).proto, Protocol::ModbusTcp);

        let dnp3 = ipv4_frame(ipv4(IPPROTO_TCP, [10, 0, 0, 2], &tcp(50000, 20000, &[0x05, 0x64, 0x0A])));
        assert_eq!(parse_frame(&dnp3).proto, Protocol::Dnp3);

        let dnp3_udp = ipv4_frame(ipv4(IPPROTO_UDP, [10, 0, 0, 2], &udp(20000, 20000, &[0x05, 0x64, 0x0A])));
        assert_eq!(parse_frame(&dnp3_udp).proto, Protocol::Dnp3);

        let ntp = ipv4_frame(ipv4(IPPROTO_UDP, [10, 0, 0, 2], &udp(123, 123, &[0x1B])));
        assert_eq!(parse_frame(&ntp).proto, Protocol::Ntp);
    }

    #[test]
    fn port_match_alone_is_not_enough() {
        // Right port, wrong framing -> stays IPv4 rather than being mislabelled.
        for (port, bad) in [
            (102u16, vec![0xDE, 0xAD, 0xBE, 0xEF]),
            (2404, vec![0x99, 0x04]),
            (502, vec![0, 1, 9, 9, 0, 6, 1, 3]),
            (20000, vec![0x01, 0x02, 0x03]),
        ] {
            let f = ipv4_frame(ipv4(IPPROTO_TCP, [10, 0, 0, 2], &tcp(50000, port, &bad)));
            assert_eq!(parse_frame(&f).proto, Protocol::Ipv4, "port {port} should not match");
        }
    }

    #[test]
    fn skips_non_first_ip_fragments() {
        let mut body = ipv4(IPPROTO_TCP, [10, 0, 0, 2], &tcp(50000, 102, &[0x03, 0x00, 0x00, 0x16]));
        body[6] = 0x00;
        body[7] = 0x10; // non-zero fragment offset
        assert_eq!(parse_frame(&ipv4_frame(body)).proto, Protocol::Ipv4);
    }

    #[test]
    fn parses_rgoose_over_udp_multicast() {
        let goose_pdu = [
            0x61, 0x15, 0x80, 0x04, b'g', b'c', b'b', b'1', // gocbRef
            0x83, 0x04, b'R', b'G', b'O', b'1', // goID
            0x85, 0x01, 0x09, // stNum
            0x87, 0x01, 0xFF, // simulation = true
            0x88, 0x01, 0x02, // confRev
        ];
        // Session header padding, then AppID (4 bytes before the 0x61 tag).
        let mut udp_payload = vec![0xA1, 0x18, 0x00, 0x00, 0x00, 0x00];
        udp_payload.extend_from_slice(&[0x80, 0x01]); // AppID 0x8001
        udp_payload.extend_from_slice(&[0x00, 0x18]); // Length
        udp_payload.extend_from_slice(&goose_pdu);

        let f = parse_frame(&ipv4_frame(ipv4(
            IPPROTO_UDP,
            [224, 0, 1, 100],
            &udp(102, 102, &udp_payload),
        )));
        assert_eq!(f.proto, Protocol::RGoose);
        assert_eq!(f.app.appid, Some(0x8001));
        assert_eq!(f.app.svid_label(), "RGO1");
        assert_eq!(f.app.noasdu, Some(9));
        assert_eq!(f.app.confrev, Some(2));
        assert_eq!(f.app.sim, Some(true));

        // The payload is what identifies it, so a site using a different
        // multicast group is still classified correctly.
        let f = parse_frame(&ipv4_frame(ipv4(
            IPPROTO_UDP,
            [239, 192, 0, 5],
            &udp(102, 102, &udp_payload),
        )));
        assert_eq!(f.proto, Protocol::RGoose);
        assert_eq!(f.app.svid_label(), "RGO1");
    }

    #[test]
    fn ordinary_ip_multicast_is_not_mistaken_for_rgoose() {
        // mDNS and SSDP are in the multicast range but carry nothing like a
        // session PDU. Counting them as R-GOOSE would inflate a protocol an
        // operator is specifically watching.
        for (dst, payload) in [
            ([224u8, 0, 0, 251], vec![0x00, 0x00, 0x84, 0x00, 0x00, 0x00]), // mDNS
            ([239, 255, 255, 250], b"NOTIFY * HTTP/1.1\r\n".to_vec()),      // SSDP
            ([224, 0, 0, 1], vec![0x11, 0x64, 0xee, 0x9b]),                 // IGMP-ish
        ] {
            let f = parse_frame(&ipv4_frame(ipv4(IPPROTO_UDP, dst, &udp(5353, 5353, &payload))));
            assert_eq!(f.proto, Protocol::Ipv4, "{dst:?} should not be R-GOOSE");
        }
    }

    #[test]
    fn conventional_iec_multicast_ranges_still_classify_without_a_parsable_payload() {
        // A session header longer than the scan window leaves the payload
        // unconfirmed; the reserved IEC ranges then act as the fallback.
        let opaque = vec![0xAA; 200];
        let f = parse_frame(&ipv4_frame(ipv4(IPPROTO_UDP, [224, 0, 1, 5], &udp(102, 102, &opaque))));
        assert_eq!(f.proto, Protocol::RGoose);
        let f = parse_frame(&ipv4_frame(ipv4(IPPROTO_UDP, [224, 0, 2, 5], &udp(102, 102, &opaque))));
        assert_eq!(f.proto, Protocol::RSv);
        // ...but only those two /24s, not the whole multicast range.
        let f = parse_frame(&ipv4_frame(ipv4(IPPROTO_UDP, [224, 0, 3, 5], &udp(102, 102, &opaque))));
        assert_eq!(f.proto, Protocol::Ipv4);
    }

    #[test]
    fn ber_length_handles_long_form_and_truncation() {
        assert_eq!(ber_len(&[0x05], 0), (5, 1));
        assert_eq!(ber_len(&[0x81, 0x80], 0), (128, 2));
        assert_eq!(ber_len(&[0x82, 0x01, 0x00], 0), (256, 3));
        // Long form claiming more bytes than exist.
        assert_eq!(ber_len(&[0x84, 0x01], 0), (0, 5));
        assert_eq!(ber_len(&[], 0), (0, 0));
    }

    #[test]
    fn strings_are_sanitised_for_display() {
        assert_eq!(&*ber_string(b"ok\x1b[31m"), "ok.[31m");
        assert_eq!(&*ber_string(&[0x00, 0xFF]), "..");
    }
}
