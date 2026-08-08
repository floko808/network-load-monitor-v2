//! Network interface enumeration.

use std::fmt;

/// One capturable interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interface {
    /// The name to hand to the capture backend.
    pub id: String,
    /// What to show a human. On Windows this is the adapter description,
    /// because the raw NPF device path is an unreadable GUID.
    pub label: String,
    /// Negotiated link speed in Mb/s, where the OS reports one.
    pub speed_mbps: Option<u32>,
}

impl fmt::Display for Interface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.label == self.id {
            f.write_str(&self.id)
        } else {
            write!(f, "{} ({})", self.label, self.id)
        }
    }
}

/// Every interface the system reports, best-effort.
pub fn list_interfaces() -> Vec<Interface> {
    #[cfg(target_os = "linux")]
    {
        linux_interfaces()
    }
    #[cfg(not(target_os = "linux"))]
    {
        dumpcap_interfaces()
    }
}

/// Match user input against either the friendly label or the backend id.
pub fn resolve<'a>(input: &str, list: &'a [Interface]) -> Option<&'a Interface> {
    list.iter()
        .find(|i| i.id == input)
        .or_else(|| list.iter().find(|i| i.label == input))
        .or_else(|| list.iter().find(|i| i.to_string() == input))
        .or_else(|| list.iter().find(|i| i.label.eq_ignore_ascii_case(input)))
}

#[cfg(target_os = "linux")]
fn linux_interfaces() -> Vec<Interface> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
        return out;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        // Reported only for interfaces with a negotiated link, and reads as
        // -1 or errors otherwise; either way it is simply omitted.
        let speed_mbps = std::fs::read_to_string(entry.path().join("speed"))
            .ok()
            .and_then(|s| s.trim().parse::<i64>().ok())
            .filter(|v| *v > 0)
            .map(|v| v as u32);
        out.push(Interface { label: name.clone(), id: name, speed_mbps });
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}

/// Ask `dumpcap -D` for the interface list.
///
/// This avoids linking against Npcap's own API: the same helper the tool
/// already depends on for capture can enumerate too, and its output carries
/// the friendly adapter names Windows users actually recognise. What it does
/// *not* carry is link speed, which is filled in separately below — without
/// it every load percentage would be measured against a guess.
#[allow(dead_code)]
fn dumpcap_interfaces() -> Vec<Interface> {
    // `mut` is used only on Windows, where the speeds are filled in below.
    #[cfg_attr(not(windows), allow(unused_mut))]
    let mut list: Vec<Interface> = crate::capture::find_dumpcap()
        .and_then(|exe| std::process::Command::new(exe).arg("-D").output().ok())
        .map(|out| {
            String::from_utf8_lossy(&out.stdout).lines().filter_map(parse_dumpcap_line).collect()
        })
        .unwrap_or_default();

    #[cfg(windows)]
    {
        if list.is_empty() {
            // Without Wireshark installed there is nothing to capture with,
            // but the adapters can still be named. Listing them beats a bare
            // "no interfaces found", which reads like a broken machine rather
            // than a missing dependency.
            list = windows::adapters_as_interfaces();
        } else {
            windows::attach_link_speeds(&mut list);
        }
    }
    list
}

/// Link-speed lookup for Windows adapters.
///
/// `dumpcap -D` identifies an adapter by its NPF device path, which embeds the
/// adapter GUID; the IP Helper API reports the negotiated speed against that
/// same GUID. Matching the two is what lets the load percentage mean anything
/// on Windows.
#[cfg(windows)]
mod windows {
    use super::Interface;
    use std::ffi::c_void;
    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
        GAA_FLAG_SKIP_MULTICAST, GAA_FLAG_SKIP_UNICAST, IP_ADAPTER_ADDRESSES_LH,
    };

    /// One network adapter as the OS describes it.
    pub struct Adapter {
        /// The adapter GUID, uppercased, braces included.
        pub guid: String,
        pub friendly_name: String,
        pub speed_mbps: Option<u32>,
    }

    /// Fill in `speed_mbps` for every interface whose device path carries a
    /// GUID the OS also reports an adapter for.
    pub fn attach_link_speeds(list: &mut [Interface]) {
        let adapters = adapters();
        for iface in list.iter_mut() {
            let id = iface.id.to_ascii_uppercase();
            if let Some(a) =
                adapters.iter().find(|a| !a.guid.is_empty() && id.contains(a.guid.as_str()))
            {
                iface.speed_mbps = a.speed_mbps;
            }
        }
    }

    /// Adapters as capture interfaces, for when `dumpcap` is unavailable.
    ///
    /// Npcap names its devices `\Device\NPF_{GUID}`, so the path can be
    /// reconstructed. Capture still needs Npcap installed; this only makes
    /// the listing informative.
    pub fn adapters_as_interfaces() -> Vec<Interface> {
        adapters()
            .into_iter()
            .map(|a| Interface {
                id: format!(r"\Device\NPF_{}", a.guid),
                label: if a.friendly_name.is_empty() { a.guid.clone() } else { a.friendly_name },
                speed_mbps: a.speed_mbps,
            })
            .collect()
    }

    /// Every adapter the OS reports.
    fn adapters() -> Vec<Adapter> {
        // AF_UNSPEC: both IPv4 and IPv6 adapters. Every address family is
        // skipped below anyway; only the adapter entries themselves matter.
        const AF_UNSPEC: u32 = 0;
        let flags = GAA_FLAG_SKIP_UNICAST
            | GAA_FLAG_SKIP_ANYCAST
            | GAA_FLAG_SKIP_MULTICAST
            | GAA_FLAG_SKIP_DNS_SERVER;

        let mut size: u32 = 15 * 1024;
        let mut buf = vec![0u8; size as usize];
        loop {
            let rc = unsafe {
                GetAdaptersAddresses(
                    AF_UNSPEC,
                    flags,
                    std::ptr::null_mut::<c_void>(),
                    buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                    &mut size,
                )
            };
            match rc {
                x if x == NO_ERROR => break,
                // The buffer size needed is only known after asking once.
                x if x == ERROR_BUFFER_OVERFLOW && (size as usize) > buf.len() => {
                    buf.resize(size as usize, 0);
                }
                _ => return Vec::new(),
            }
        }

        let mut out = Vec::new();
        let mut cur = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !cur.is_null() {
            // SAFETY: the list was just written by the OS into `buf`, and
            // every pointer walked here comes from that same structure.
            unsafe {
                out.push(Adapter {
                    guid: ansi_string((*cur).AdapterName).to_ascii_uppercase(),
                    friendly_name: wide_string((*cur).FriendlyName),
                    speed_mbps: link_speed_mbps((*cur).TransmitLinkSpeed),
                });
                cur = (*cur).Next;
            }
        }
        out
    }

    /// Convert a reported link speed to Mb/s, rejecting the "unknown" values.
    ///
    /// Windows reports `u64::MAX` when a driver does not know, and a
    /// disconnected adapter reports zero.
    fn link_speed_mbps(bits_per_s: u64) -> Option<u32> {
        if bits_per_s == 0 || bits_per_s == u64::MAX {
            return None;
        }
        let mbps = bits_per_s / 1_000_000;
        // Beyond 400 Gb/s this is far more likely to be a bogus driver value
        // than a real link.
        if !(1..=400_000).contains(&mbps) {
            return None;
        }
        Some(mbps as u32)
    }

    unsafe fn ansi_string(p: *const u8) -> String {
        if p.is_null() {
            return String::new();
        }
        let mut len = 0;
        while *p.add(len) != 0 {
            len += 1;
        }
        String::from_utf8_lossy(std::slice::from_raw_parts(p, len)).into_owned()
    }

    /// Read a null-terminated UTF-16 string, as Windows returns for names.
    unsafe fn wide_string(p: *const u16) -> String {
        if p.is_null() {
            return String::new();
        }
        let mut len = 0;
        while *p.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }
}

/// Parse one `dumpcap -D` line: `1. \Device\NPF_{GUID} (Ethernet 2)`.
fn parse_dumpcap_line(line: &str) -> Option<Interface> {
    let line = line.trim();
    let rest = line.split_once('.').map(|(_, r)| r.trim()).unwrap_or(line);
    if rest.is_empty() {
        return None;
    }
    let (id, label) = match (rest.find(" ("), rest.ends_with(')')) {
        (Some(i), true) => (rest[..i].to_string(), rest[i + 2..rest.len() - 1].to_string()),
        _ => (rest.to_string(), rest.to_string()),
    };
    Some(Interface { id, label, speed_mbps: None })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(id: &str, label: &str) -> Interface {
        Interface { id: id.into(), label: label.into(), speed_mbps: None }
    }

    #[test]
    fn parses_dumpcap_listing_lines() {
        let i = parse_dumpcap_line(r"1. \Device\NPF_{ABC-123} (Ethernet 2)").unwrap();
        assert_eq!(i.id, r"\Device\NPF_{ABC-123}");
        assert_eq!(i.label, "Ethernet 2");

        // No friendly name available.
        let i = parse_dumpcap_line("2. eth0").unwrap();
        assert_eq!(i.id, "eth0");
        assert_eq!(i.label, "eth0");

        assert!(parse_dumpcap_line("").is_none());
    }

    #[test]
    fn resolves_by_id_label_or_full_display() {
        let list = vec![iface(r"\Device\NPF_{X}", "Ethernet 2"), iface("eth0", "eth0")];
        assert_eq!(resolve(r"\Device\NPF_{X}", &list).unwrap().label, "Ethernet 2");
        assert_eq!(resolve("Ethernet 2", &list).unwrap().id, r"\Device\NPF_{X}");
        assert_eq!(resolve(r"Ethernet 2 (\Device\NPF_{X})", &list).unwrap().id, r"\Device\NPF_{X}");
        assert_eq!(resolve("eth0", &list).unwrap().id, "eth0");
        assert!(resolve("nope", &list).is_none());
    }

    #[test]
    fn display_omits_a_redundant_label() {
        assert_eq!(iface("eth0", "eth0").to_string(), "eth0");
        assert_eq!(iface(r"\Device\X", "Ethernet").to_string(), r"Ethernet (\Device\X)");
    }
}
