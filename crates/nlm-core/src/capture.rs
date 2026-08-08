//! Live capture backends.
//!
//! Two are supported, tried in order:
//!
//! 1. A raw `AF_PACKET` socket, which needs `CAP_NET_RAW` (root is one way to
//!    have it, but not the only one — which is why availability is decided by
//!    *trying to open one*, not by checking for uid 0).
//! 2. `dumpcap`, the small setuid-ish helper Wireshark ships, which is
//!    normally usable without root once the user is in the `wireshark` group
//!    on Linux, or once Npcap's admin-only restriction is lifted on Windows.
//!
//! If neither works the caller gets an actionable, platform-specific message
//! rather than a capture that silently sees nothing.

use crate::pcap::CaptureReader;
use std::fmt;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

/// How frames are being collected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Backend {
    RawSocket,
    Dumpcap(PathBuf),
}

impl fmt::Display for Backend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Backend::RawSocket => f.write_str("raw socket"),
            Backend::Dumpcap(p) => write!(f, "dumpcap ({})", p.display()),
        }
    }
}

#[derive(Debug)]
pub enum CaptureError {
    NoBackend,
    Start(String),
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CaptureError::NoBackend => f.write_str(NO_BACKEND_HELP),
            CaptureError::Start(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for CaptureError {}

#[cfg(windows)]
const NO_BACKEND_HELP: &str = "\
no capture backend available.

Capturing on Windows needs a packet-capture driver:
  1. Install Wireshark (https://www.wireshark.org/), which bundles Npcap.
  2. Then either run this program as Administrator, or re-run the Npcap
     installer and uncheck \"Restrict Npcap driver's access to Administrators
     only\" so it can capture without elevation.";

#[cfg(not(windows))]
const NO_BACKEND_HELP: &str = "\
no capture backend available.

Capturing needs permission to open a raw socket. Any one of these works:
  * run with sudo
  * grant the binary the capability:  sudo setcap cap_net_raw+eip <this binary>
  * install wireshark-common and join the wireshark group:
        sudo usermod -aG wireshark $USER   (then log out and back in)
    which lets the dumpcap fallback capture without root.";

/// Pick the best backend the current process can actually use.
pub fn select_backend() -> Result<Backend, CaptureError> {
    #[cfg(target_os = "linux")]
    if raw::available() {
        return Ok(Backend::RawSocket);
    }
    if let Some(path) = find_dumpcap() {
        return Ok(Backend::Dumpcap(path));
    }
    Err(CaptureError::NoBackend)
}

/// Locate Wireshark's `dumpcap` helper.
///
/// The Windows installer does not put Wireshark on `PATH`, so the standard
/// install locations and then the registry are checked before giving up.
pub fn find_dumpcap() -> Option<PathBuf> {
    let exe = if cfg!(windows) { "dumpcap.exe" } else { "dumpcap" };
    if let Some(p) = search_path(exe) {
        return Some(p);
    }
    #[cfg(windows)]
    {
        windows_dumpcap()
    }
    #[cfg(not(windows))]
    {
        ["/usr/bin", "/usr/sbin", "/usr/local/bin", "/opt/wireshark/bin"]
            .iter()
            .map(|d| Path::new(d).join(exe))
            .find(|p| p.is_file())
    }
}

fn search_path(exe: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).map(|d| d.join(exe)).find(|p| p.is_file())
}

#[cfg(windows)]
fn windows_dumpcap() -> Option<PathBuf> {
    for var in ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"] {
        if let Some(base) = std::env::var_os(var) {
            let p = Path::new(&base).join("Wireshark").join("dumpcap.exe");
            if p.is_file() {
                return Some(p);
            }
        }
    }
    // Fall back to wherever the installer recorded itself.
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    for key in ["SOFTWARE\\Wireshark", "SOFTWARE\\WOW6432Node\\Wireshark"] {
        if let Ok(k) = hklm.open_subkey(key) {
            if let Ok(dir) = k.get_value::<String, _>("InstallDir") {
                let p = Path::new(&dir).join("dumpcap.exe");
                if p.is_file() {
                    return Some(p);
                }
            }
        }
    }
    None
}

/// Where captured frames are delivered.
///
/// This is a trait rather than a plain closure because a sink that batches
/// needs to know about more than arrivals: without [`idle`](FrameSink::idle)
/// and [`finish`](FrameSink::finish), the tail of a burst would sit in a
/// half-full batch until the *next* burst arrived — landing in the wrong
/// window, minutes later, on exactly the sparse protocols where accuracy
/// matters most.
pub trait FrameSink: Send + 'static {
    /// One captured frame, with its length on the wire and, where the backend
    /// knows it, the time it was actually captured.
    ///
    /// The timestamp matters because a backend can deliver frames later and
    /// more unevenly than they arrived on the wire; without it, rates measure
    /// how the frames reached us rather than how they crossed the link.
    fn frame(&mut self, data: &[u8], wire_len: u64, ts: Option<f64>);

    /// No frame arrived within the backend's poll interval.
    fn idle(&mut self) {}

    /// The capture is ending; flush anything still buffered.
    fn finish(&mut self) {}
}

/// Parses, filters and accumulates frames into a [`Stats`](crate::stats::Stats).
///
/// Frames are folded into a thread-local batch first, so the shared lock is
/// taken once per batch instead of once per frame.
pub struct StatsSink {
    stats: Arc<crate::stats::Stats>,
    filter: crate::filter::FrameFilter,
    batch: crate::stats::BatchAccum,
}

impl StatsSink {
    pub fn new(stats: Arc<crate::stats::Stats>, filter: crate::filter::FrameFilter) -> StatsSink {
        StatsSink {
            stats,
            filter,
            batch: crate::stats::BatchAccum::new(
                crate::consts::BATCH_PKTS,
                crate::consts::BATCH_SECS,
            ),
        }
    }

    fn flush(&mut self) {
        if self.batch.is_empty() {
            return;
        }
        let batch = self.batch.take();
        self.stats.merge_batch(&batch);
    }
}

impl FrameSink for StatsSink {
    fn frame(&mut self, data: &[u8], wire_len: u64, ts: Option<f64>) {
        let parsed = crate::parse::parse_frame(data);
        // Filtered frames are dropped before they touch any counter.
        if !self.filter.matches(&parsed) {
            return;
        }
        if self.batch.push(&parsed, wire_len, ts) {
            self.flush();
        }
    }

    fn idle(&mut self) {
        self.flush();
    }

    fn finish(&mut self) {
        self.flush();
    }
}

/// A running capture. Dropping it stops the capture and waits for the thread.
pub struct Capture {
    backend: Backend,
    stop: Arc<AtomicBool>,
    running: Arc<AtomicBool>,
    child: Arc<Mutex<Option<Child>>>,
    error: Arc<Mutex<Option<String>>>,
    handle: Option<JoinHandle<()>>,
}

impl Capture {
    /// Begin capturing on `iface`, delivering frames to `sink` from a
    /// dedicated capture thread.
    pub fn start<S>(backend: Backend, iface: &str, sink: S) -> Result<Capture, CaptureError>
    where
        S: FrameSink,
    {
        let stop = Arc::new(AtomicBool::new(false));
        let running = Arc::new(AtomicBool::new(true));
        let child: Arc<Mutex<Option<Child>>> = Arc::new(Mutex::new(None));
        let error: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

        let handle = match &backend {
            Backend::RawSocket => {
                #[cfg(target_os = "linux")]
                {
                    raw::spawn(iface, sink, stop.clone(), running.clone(), error.clone())?
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = (iface, sink);
                    return Err(CaptureError::NoBackend);
                }
            }
            Backend::Dumpcap(exe) => spawn_dumpcap(
                exe,
                iface,
                sink,
                stop.clone(),
                running.clone(),
                child.clone(),
                error.clone(),
            )?,
        };

        Ok(Capture { backend, stop, running, child, error, handle: Some(handle) })
    }

    pub fn backend(&self) -> &Backend {
        &self.backend
    }

    /// Whether the capture thread is still delivering frames.
    ///
    /// This stays `true` for a moment after [`stop`](Self::stop): `dumpcap`
    /// buffers, so frames captured just before the stop may still be in
    /// flight through the pipe. Callers that render a final summary should
    /// wait for this to clear, or they will under-report the last burst.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Ask the capture to wind down. Returns immediately.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Ok(mut guard) = self.child.lock() {
            if let Some(child) = guard.as_mut() {
                let _ = child.kill();
            }
        }
    }

    /// Any error the capture thread hit after starting.
    pub fn take_error(&self) -> Option<String> {
        self.error.lock().ok().and_then(|mut e| e.take())
    }

    /// Stop and wait for the capture thread to finish.
    pub fn shutdown(&mut self) {
        self.stop();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Read frames from `dumpcap`'s stdout as a pcap stream.
#[allow(clippy::too_many_arguments)]
fn spawn_dumpcap<S>(
    exe: &Path,
    iface: &str,
    mut sink: S,
    stop: Arc<AtomicBool>,
    running: Arc<AtomicBool>,
    child_slot: Arc<Mutex<Option<Child>>>,
    error: Arc<Mutex<Option<String>>>,
) -> Result<JoinHandle<()>, CaptureError>
where
    S: FrameSink,
{
    let mut child = Command::new(exe)
        // -w - writes the capture to stdout; -F pcap keeps the framing simple
        // to read; -q suppresses the periodic packet-count chatter.
        .args(["-i", iface, "-w", "-", "-F", "pcap", "-q"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| CaptureError::Start(format!("could not run {}: {e}", exe.display())))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| CaptureError::Start("dumpcap produced no output stream".into()))?;
    let stderr = child.stderr.take();
    *child_slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(child);

    let handle = std::thread::spawn(move || {
        // Held open so it can be reported if the stream turns out to be unusable.
        let complain = |error: &Arc<Mutex<Option<String>>>, msg: String| {
            if let Ok(mut slot) = error.lock() {
                if slot.is_none() {
                    *slot = Some(msg);
                }
            }
        };

        let mut reader = match CaptureReader::new(BufReader::with_capacity(1 << 20, stdout)) {
            Ok(r) => r,
            Err(e) => {
                // dumpcap failing to open the interface shows up here as an
                // unreadable stream; its own message is far more useful.
                let detail = stderr
                    .map(|mut s| {
                        use std::io::Read;
                        let mut buf = String::new();
                        let _ = s.read_to_string(&mut buf);
                        buf.trim().to_string()
                    })
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| e.to_string());
                complain(&error, format!("dumpcap could not start capturing: {detail}"));
                running.store(false, Ordering::Relaxed);
                return;
            }
        };

        while !stop.load(Ordering::Relaxed) {
            match reader.next_frame() {
                Ok(Some(frame)) => {
                    let size = frame.orig_len.max(frame.data.len() as u32) as u64;
                    // dumpcap records the capture time in each pcap record,
                    // which is the truth about when the frame crossed the
                    // link regardless of when the pipe hands it over.
                    sink.frame(frame.data, size, Some(frame.ts));
                }
                Ok(None) => break,
                Err(e) => {
                    if !stop.load(Ordering::Relaxed) {
                        complain(&error, format!("capture stream ended: {e}"));
                    }
                    break;
                }
            }
        }
        sink.finish();
        running.store(false, Ordering::Relaxed);
    });

    Ok(handle)
}

// =========================================================================
// Raw AF_PACKET socket (Linux)
// =========================================================================

#[cfg(target_os = "linux")]
mod raw {
    use super::CaptureError;
    use std::ffi::CString;
    use std::io;
    use std::os::raw::c_void;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::JoinHandle;

    /// `ETH_P_ALL` in network byte order: capture every EtherType.
    fn eth_p_all() -> libc::c_int {
        (0x0003u16.to_be()) as libc::c_int
    }

    /// Whether this process can open a raw packet socket at all.
    ///
    /// Determined by trying, not by checking for root: `CAP_NET_RAW` can be
    /// granted to an unprivileged binary, and a uid check would wrongly send
    /// those users down the dumpcap path.
    pub fn available() -> bool {
        unsafe {
            let fd = libc::socket(libc::AF_PACKET, libc::SOCK_RAW, eth_p_all());
            if fd < 0 {
                false
            } else {
                libc::close(fd);
                true
            }
        }
    }

    struct Socket {
        fd: libc::c_int,
    }

    impl Drop for Socket {
        fn drop(&mut self) {
            unsafe { libc::close(self.fd) };
        }
    }

    impl Socket {
        fn open(iface: &str) -> io::Result<Socket> {
            let name = CString::new(iface)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid interface name"))?;
            let idx = unsafe { libc::if_nametoindex(name.as_ptr()) };
            if idx == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no such interface: {iface}"),
                ));
            }

            let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, eth_p_all()) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let sock = Socket { fd };

            let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            addr.sll_family = libc::AF_PACKET as u16;
            addr.sll_protocol = 0x0003u16.to_be();
            addr.sll_ifindex = idx as i32;
            let rc = unsafe {
                libc::bind(
                    sock.fd,
                    &addr as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
                )
            };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }

            // A generous receive buffer: at Sampled Values rates the kernel
            // will drop frames long before the classifier is the bottleneck.
            let bufsize: libc::c_int = 8 * 1024 * 1024;
            unsafe {
                libc::setsockopt(
                    sock.fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUF,
                    &bufsize as *const _ as *const c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }

            // Time out receives so a stop request is acted on promptly even
            // on a completely silent link.
            let tv = libc::timeval { tv_sec: 0, tv_usec: 200_000 };
            unsafe {
                libc::setsockopt(
                    sock.fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVTIMEO,
                    &tv as *const _ as *const c_void,
                    std::mem::size_of::<libc::timeval>() as libc::socklen_t,
                );
            }
            Ok(sock)
        }

        /// `Ok(None)` means the receive timed out, not that anything failed.
        fn recv(&self, buf: &mut [u8]) -> io::Result<Option<usize>> {
            let n = unsafe {
                libc::recv(self.fd, buf.as_mut_ptr() as *mut c_void, buf.len(), 0)
            };
            if n >= 0 {
                return Ok(Some(n as usize));
            }
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EAGAIN) | Some(libc::EINTR) => Ok(None),
                _ => Err(err),
            }
        }
    }

    pub fn spawn<S>(
        iface: &str,
        mut sink: S,
        stop: Arc<AtomicBool>,
        running: Arc<AtomicBool>,
        error: Arc<Mutex<Option<String>>>,
    ) -> Result<JoinHandle<()>, CaptureError>
    where
        S: super::FrameSink,
    {
        let sock = Socket::open(iface)
            .map_err(|e| CaptureError::Start(format!("could not capture on {iface}: {e}")))?;

        Ok(std::thread::spawn(move || {
            let mut buf = vec![0u8; 65_536];
            while !stop.load(Ordering::Relaxed) {
                match sock.recv(&mut buf) {
                    // Frames arrive as they are captured here, so arrival
                    // time already is capture time and no timestamp is needed.
                    Ok(Some(n)) if n > 0 => sink.frame(&buf[..n], n as u64, None),
                    // A receive timeout is the natural moment to hand over a
                    // partially filled batch: the link is quiet right now.
                    Ok(_) => sink.idle(),
                    Err(e) => {
                        if !stop.load(Ordering::Relaxed) {
                            if let Ok(mut slot) = error.lock() {
                                if slot.is_none() {
                                    *slot = Some(format!("capture failed: {e}"));
                                }
                            }
                        }
                        break;
                    }
                }
            }
            sink.finish();
            running.store(false, Ordering::Relaxed);
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_names_are_readable() {
        assert_eq!(Backend::RawSocket.to_string(), "raw socket");
        assert!(Backend::Dumpcap(PathBuf::from("/usr/bin/dumpcap"))
            .to_string()
            .contains("/usr/bin/dumpcap"));
    }

    #[test]
    fn missing_backend_explains_how_to_fix_it() {
        let msg = CaptureError::NoBackend.to_string();
        assert!(msg.contains("no capture backend available"));
        // The message must name a concrete remedy, not just state the problem.
        #[cfg(not(windows))]
        assert!(msg.contains("cap_net_raw") && msg.contains("wireshark"));
        #[cfg(windows)]
        assert!(msg.contains("Npcap"));
    }
}
