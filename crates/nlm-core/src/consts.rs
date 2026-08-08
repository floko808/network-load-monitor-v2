//! EtherTypes, well-known ports, and the protocol display tables.

// ---- EtherTypes ---------------------------------------------------------
/// IEEE 802.1Q VLAN tag.
pub const ET_VLAN: u16 = 0x8100;
/// IEEE 802.1ad QinQ (service VLAN) tag.
pub const ET_QINQ: u16 = 0x88A8;
/// IEC 61850-8-1 GOOSE.
pub const ET_GOOSE: u16 = 0x88B8;
/// IEC 61850-9-2 Sampled Values.
pub const ET_SV: u16 = 0x88BA;
/// Legacy GSSE (UCA 2.0).
pub const ET_GSSE: u16 = 0x88B9;
/// IEEE 1588 PTP.
pub const ET_PTP: u16 = 0x88F7;
/// IEC 62439-3 HSR in-frame tag.
pub const ET_HSR: u16 = 0x892F;
pub const ET_IPV4: u16 = 0x0800;
pub const ET_IPV6: u16 = 0x86DD;
pub const ET_ARP: u16 = 0x0806;
pub const ET_LLDP: u16 = 0x88CC;
/// PRP Redundancy Control Trailer suffix (last 2 bytes of the frame).
pub const PRP_SUF: u16 = 0x88FB;

// ---- Well-known transport ports ----------------------------------------
/// ISO/COTP-encapsulated MMS (RFC 1006) — IEC 61850-8-1.
pub const PORT_MMS: u16 = 102;
/// Network Time Protocol.
pub const PORT_NTP: u16 = 123;
/// Modbus TCP.
pub const PORT_MODBUS: u16 = 502;
/// IEC 60870-5-104.
pub const PORT_IEC104: u16 = 2404;
/// DNP3, over TCP or UDP.
pub const PORT_DNP3: u16 = 20000;

// ---- IP protocol numbers ------------------------------------------------
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

// ---- Identity -----------------------------------------------------------
pub const SOFTWARE_NAME: &str = "Network Load Monitor V2";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const LICENSE_NAME: &str = "MIT";

// ---- Defaults -----------------------------------------------------------
/// Default link speed in Mb/s used for the load-percentage calculation.
pub const DEFAULT_LINK_MBPS: f64 = 100.0;
/// Default capture duration in seconds (0 = run until stopped).
pub const DEFAULT_DURATION_S: f64 = 10.0;
/// Default statistics window / display refresh in seconds.
pub const DEFAULT_REFRESH_S: f64 = 1.0;

// ---- Batching -----------------------------------------------------------
/// Flush a thread-local batch into the shared map after this many packets.
pub const BATCH_PKTS: usize = 200;
/// ...or after this long, whichever comes first.
pub const BATCH_SECS: f64 = 0.10;
/// Emit an offline-load progress callback every this many packets.
pub const PCAP_PROGRESS_EVERY: u64 = 2000;
