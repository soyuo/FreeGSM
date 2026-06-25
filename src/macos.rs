//! macOS DNS interception via pf.
//!
//! macOS has no WinDivert equivalent. For DNS-over-HTTPS mode we install a
//! temporary pf anchor that redirects TCP/UDP port 53 to local DoH proxies.

use std::fs::File;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::os::raw::{c_int, c_ulong};
use std::os::unix::io::{AsRawFd, RawFd};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use socket2::{Domain, Protocol, Socket, Type};

use crate::config;
use crate::dnsutil::describe_query;
use crate::doh;
use crate::dpi;

static STOP: AtomicBool = AtomicBool::new(false);

const ANCHOR: &str = "com.apple/freegsm";

fn pf_rules() -> Result<String> {
    let upstream_hi = config::UPSTREAM_PORT_BASE + config::UPSTREAM_PORT_COUNT - 1;
    let iface = default_interface()?;
    Ok(format!(
        "no rdr inet proto tcp from any port {}:{} to any port 443\n\
         no rdr on lo0 inet proto tcp from any port {}:{} to any port 443\n\
         no rdr inet proto tcp from any to any port {{{}, {}}}\n\
         no rdr on lo0 inet proto tcp from any to any port {{{}, {}}}\n\
         rdr pass inet proto udp from any to any port 53 -> 127.0.0.1 port {}\n\
         rdr pass inet proto tcp from any to any port 53 -> 127.0.0.1 port {}\n\
         rdr pass inet proto tcp from any to any port 443 -> 127.0.0.1 port {}\n\
         rdr pass on lo0 inet proto tcp from any to any port 443 -> 127.0.0.1 port {}\n\
         block drop quick inet proto udp from any to any port 443\n\
         pass out on {} inet route-to (lo0 127.0.0.1) proto tcp from any to any port 443\n",
        config::UPSTREAM_PORT_BASE,
        upstream_hi,
        config::UPSTREAM_PORT_BASE,
        upstream_hi,
        config::TCP_PROXY_PORT,
        config::HTTPS_PROXY_PORT,
        config::TCP_PROXY_PORT,
        config::HTTPS_PROXY_PORT,
        config::TCP_PROXY_PORT,
        config::TCP_PROXY_PORT,
        config::HTTPS_PROXY_PORT,
        config::HTTPS_PROXY_PORT,
        iface,
    ))
}

fn default_interface() -> Result<String> {
    let output = Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .context("detecting default route interface")?;
    if !output.status.success() {
        bail!(
            "route -n get default failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("interface:") {
            return Ok(rest.trim().to_string());
        }
    }
    bail!("could not find default route interface")
}

pub fn request_stop() {
    STOP.store(true, Ordering::SeqCst);
}

pub fn is_stopped() -> bool {
    STOP.load(Ordering::SeqCst)
}

pub struct Runtime {
    pf: PfAnchor,
    nat: NatHandle,
}

impl Drop for Runtime {
    fn drop(&mut self) {
        request_stop();
        self.pf.clear();
    }
}

pub fn start() -> Result<Runtime> {
    STOP.store(false, Ordering::SeqCst);

    start_udp_proxy()?;
    start_tcp_proxy()?;
    let nat = NatHandle::open()?;
    if config::get().dpi_bypass {
        start_https_relay(nat.clone())?;
    }

    let pf = PfAnchor::install()?;
    Ok(Runtime { pf, nat })
}

struct PfAnchor {
    token: Option<String>,
}

impl PfAnchor {
    fn install() -> Result<Self> {
        let tmp = std::env::temp_dir().join("freegsm-pf.conf");
        std::fs::write(&tmp, pf_rules()?).context("writing temporary pf rules")?;

        run_pfctl(&["-a", ANCHOR, "-f", tmp.to_string_lossy().as_ref()])
            .context("loading pf anchor")?;

        let enable = Command::new("pfctl")
            .arg("-E")
            .output()
            .context("running pfctl -E")?;
        if !enable.status.success() {
            bail!(
                "enabling pf failed: {}",
                String::from_utf8_lossy(&enable.stderr).trim()
            );
        }
        let pfctl_text = format!(
            "{}\n{}",
            String::from_utf8_lossy(&enable.stdout),
            String::from_utf8_lossy(&enable.stderr)
        );
        let token = pfctl_text
            .split_whitespace()
            .rev()
            .find(|part| part.chars().all(|c| c.is_ascii_alphanumeric()))
            .map(str::to_owned);

        log::info!(target: "freegsm.macos",
            "pf anchor {ANCHOR} loaded; DNS TCP/UDP :53 redirects to 127.0.0.1:{}",
            config::TCP_PROXY_PORT);
        if config::get().dpi_bypass {
            log::info!(target: "freegsm.macos",
                "TCP/443 redirects to 127.0.0.1:{}; UDP/443 is dropped to force TCP fallback",
                config::HTTPS_PROXY_PORT);
        }
        Ok(Self { token })
    }

    fn clear(&mut self) {
        let _ = run_pfctl(&["-a", ANCHOR, "-F", "all"]);
        if let Some(token) = self.token.take() {
            let _ = run_pfctl(&["-X", &token]);
        }
        log::info!(target: "freegsm.macos", "pf anchor {ANCHOR} cleared");
    }
}

#[derive(Clone)]
struct NatHandle(std::sync::Arc<NatHandleInner>);

struct NatHandleInner {
    file: File,
}

unsafe impl Send for NatHandle {}
unsafe impl Sync for NatHandle {}

impl AsRawFd for NatHandle {
    fn as_raw_fd(&self) -> RawFd {
        self.0.file.as_raw_fd()
    }
}

impl NatHandle {
    fn open() -> Result<Self> {
        let file = File::open("/dev/pf").context("opening /dev/pf for NAT lookups")?;
        Ok(Self(std::sync::Arc::new(NatHandleInner { file })))
    }
}

extern "C" {
    fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PfAddr {
    addr: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PfiocNatlook {
    saddr: PfAddr,
    daddr: PfAddr,
    rsaddr: PfAddr,
    rdaddr: PfAddr,
    sport: u16,
    dport: u16,
    rsport: u16,
    rdport: u16,
    af: u8,
    proto: u8,
    direction: u8,
    log: u8,
}

impl Default for PfiocNatlook {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

const fn diocnatlook_ioctl() -> c_ulong {
    0xC0000000 | ((std::mem::size_of::<PfiocNatlook>() as c_ulong) << 16) | (0x44 << 8) | 23
}

const DIOCNATLOOK: c_ulong = diocnatlook_ioctl();
const AF_INET: u8 = 2;
const IPPROTO_TCP: u8 = 6;
const PF_OUT: u8 = 1;

fn original_dest(pf: &NatHandle, client_addr: SocketAddr, local_addr: SocketAddr) -> Result<SocketAddrV4> {
    let (SocketAddr::V4(client), SocketAddr::V4(local)) = (client_addr, local_addr) else {
        bail!("only IPv4 transparent HTTPS is currently supported");
    };

    let mut src = [0u8; 16];
    src[..4].copy_from_slice(&client.ip().octets());
    let mut dst = [0u8; 16];
    dst[..4].copy_from_slice(&local.ip().octets());

    let mut nl = PfiocNatlook {
        saddr: PfAddr { addr: src },
        daddr: PfAddr { addr: dst },
        sport: client.port().to_be(),
        dport: local.port().to_be(),
        af: AF_INET,
        proto: IPPROTO_TCP,
        direction: PF_OUT,
        ..PfiocNatlook::default()
    };

    let mut ret = unsafe { ioctl(pf.as_raw_fd(), DIOCNATLOOK, &mut nl as *mut PfiocNatlook) };
    if ret < 0 {
        nl.direction = 0;
        ret = unsafe { ioctl(pf.as_raw_fd(), DIOCNATLOOK, &mut nl as *mut PfiocNatlook) };
    }
    if ret < 0 {
        return Err(std::io::Error::last_os_error()).context("DIOCNATLOOK failed");
    }

    let mut ip = [0u8; 4];
    ip.copy_from_slice(&nl.rdaddr.addr[..4]);
    Ok(SocketAddrV4::new(Ipv4Addr::from(ip), u16::from_be(nl.rdport)))
}

fn run_pfctl(args: &[&str]) -> Result<()> {
    let output = Command::new("pfctl")
        .args(args)
        .output()
        .with_context(|| format!("running pfctl {}", args.join(" ")))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(anyhow!(
            "pfctl {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn start_udp_proxy() -> Result<()> {
    let socket = UdpSocket::bind(("127.0.0.1", config::TCP_PROXY_PORT))
        .with_context(|| format!("binding UDP DNS proxy on 127.0.0.1:{}", config::TCP_PROXY_PORT))?;
    socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .context("setting UDP read timeout")?;

    std::thread::Builder::new()
        .name("macos-udp-dns".into())
        .spawn(move || udp_loop(socket))
        .context("spawning UDP DNS proxy")?;
    log::info!(target: "freegsm.macos",
        "UDP DoH proxy listening on 127.0.0.1:{}", config::TCP_PROXY_PORT);
    Ok(())
}

fn udp_loop(socket: UdpSocket) {
    let mut buf = vec![0u8; 4096];
    while !is_stopped() {
        let (n, peer) = match socket.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(e) => {
                log::warn!(target: "freegsm.macos", "UDP recv failed: {e}");
                continue;
            }
        };

        let query = &buf[..n];
        let desc = describe_query(query);
        log::info!(target: "freegsm.udp", "[INTERCEPT] UDP  {desc}  (from {peer})");
        match doh::resolve(query) {
            Ok(answer) => {
                log::info!(target: "freegsm.udp", "[RESOLVED]  UDP  {desc}  -> {} bytes", answer.len());
                let _ = socket.send_to(&answer, peer);
            }
            Err(e) => log::warn!(target: "freegsm.udp", "[FAILED]    UDP  {desc}  -> DoH error: {e:#}; dropped"),
        }
    }
}

fn start_tcp_proxy() -> Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", config::TCP_PROXY_PORT))
        .with_context(|| format!("binding TCP DNS proxy on 127.0.0.1:{}", config::TCP_PROXY_PORT))?;
    listener
        .set_nonblocking(true)
        .context("setting TCP listener nonblocking")?;

    std::thread::Builder::new()
        .name("macos-tcp-dns".into())
        .spawn(move || tcp_loop(listener))
        .context("spawning TCP DNS proxy")?;
    log::info!(target: "freegsm.macos",
        "TCP DoH proxy listening on 127.0.0.1:{}", config::TCP_PROXY_PORT);
    Ok(())
}

fn start_https_relay(nat: NatHandle) -> Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", config::HTTPS_PROXY_PORT))
        .with_context(|| format!("binding HTTPS relay on 127.0.0.1:{}", config::HTTPS_PROXY_PORT))?;
    listener
        .set_nonblocking(true)
        .context("setting HTTPS listener nonblocking")?;

    std::thread::Builder::new()
        .name("macos-https-relay".into())
        .spawn(move || https_loop(listener, nat))
        .context("spawning HTTPS relay")?;
    log::info!(target: "freegsm.https",
        "HTTPS splitting relay listening on 127.0.0.1:{} (upstream ports {}-{})",
        config::HTTPS_PROXY_PORT,
        config::UPSTREAM_PORT_BASE,
        config::UPSTREAM_PORT_BASE + config::UPSTREAM_PORT_COUNT - 1);
    Ok(())
}

fn https_loop(listener: TcpListener, nat: NatHandle) {
    while !is_stopped() {
        match listener.accept() {
            Ok((stream, peer)) => {
                let local = match stream.local_addr() {
                    Ok(addr) => addr,
                    Err(e) => {
                        log::warn!(target: "freegsm.https", "local_addr failed: {e}");
                        continue;
                    }
                };
                let nat = nat.clone();
                std::thread::spawn(move || serve_https_client(stream, nat, peer, local));
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => log::warn!(target: "freegsm.https", "HTTPS accept failed: {e}"),
        }
    }
}

static NEXT_PORT: AtomicU32 = AtomicU32::new(0);

fn connect_reserved(server: SocketAddrV4) -> Result<TcpStream> {
    let base = config::UPSTREAM_PORT_BASE;
    let count = config::UPSTREAM_PORT_COUNT as u32;
    let mut last_err: Option<std::io::Error> = None;

    for _ in 0..count {
        let n = NEXT_PORT.fetch_add(1, Ordering::Relaxed);
        let port = base + (n % count) as u16;
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
            .context("creating upstream socket")?;
        let _ = socket.set_reuse_address(true);
        let bind_addr: SocketAddr = (Ipv4Addr::UNSPECIFIED, port).into();
        if let Err(e) = socket.bind(&bind_addr.into()) {
            last_err = Some(e);
            continue;
        }
        let _ = socket.set_nodelay(true);
        socket
            .connect_timeout(&SocketAddr::V4(server).into(), config::HTTPS_CONNECT_TIMEOUT)
            .with_context(|| format!("connecting upstream {server}"))?;
        return Ok(socket.into());
    }

    Err(anyhow!("no free upstream port in reserved range ({last_err:?})"))
}

fn serve_https_client(mut client: TcpStream, nat: NatHandle, peer: SocketAddr, local: SocketAddr) {
    let server = match original_dest(&nat, peer, local) {
        Ok(dest) => dest,
        Err(e) => {
            log::warn!(target: "freegsm.https", "[HTTPS] original destination lookup failed: {e:#}");
            return;
        }
    };
    let mut upstream = match connect_reserved(server) {
        Ok(stream) => stream,
        Err(e) => {
            log::warn!(target: "freegsm.https", "[HTTPS] upstream {server} failed: {e:#}");
            return;
        }
    };

    let _ = client.set_read_timeout(Some(config::HTTPS_FIRST_READ_TIMEOUT));
    let mut buf = vec![0u8; 65535];
    let first_len = match client.read(&mut buf) {
        Ok(0) | Err(_) => return,
        Ok(n) => n,
    };
    let _ = client.set_read_timeout(None);
    let first = &buf[..first_len];

    if first.first() == Some(&dpi::TLS_HANDSHAKE) {
        let segs = dpi::split_hello(first, config::SPLIT_MIN, config::SPLIT_MAX);
        log::info!(target: "freegsm.https",
            "[HTTPS] {server}  SNI={}  ClientHello {}B -> {} TLS records",
            dpi::sni_name(first), first.len(), segs.len());
        for seg in &segs {
            if upstream.write_all(seg).is_err() {
                return;
            }
        }
    } else if upstream.write_all(first).is_err() {
        return;
    }

    let (Ok(client_rx), Ok(upstream_rx)) = (client.try_clone(), upstream.try_clone()) else {
        return;
    };
    let reverse = std::thread::Builder::new()
        .name("macos-https-pump".into())
        .spawn(move || pump(upstream_rx, client_rx));
    pump(client, upstream);
    if let Ok(handle) = reverse {
        let _ = handle.join();
    }
}

fn pump(mut src: TcpStream, mut dst: TcpStream) {
    let mut buf = vec![0u8; 65535];
    loop {
        match src.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if dst.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = dst.shutdown(std::net::Shutdown::Write);
}

fn tcp_loop(listener: TcpListener) {
    while !is_stopped() {
        match listener.accept() {
            Ok((stream, peer)) => {
                std::thread::spawn(move || serve_tcp_client(stream, peer.to_string()));
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => log::warn!(target: "freegsm.macos", "TCP accept failed: {e}"),
        }
    }
}

fn recv_exactly(sock: &mut TcpStream, n: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    let mut got = 0;
    while got < n {
        match sock.read(&mut buf[got..]) {
            Ok(0) => {
                buf.truncate(got);
                return Ok(buf);
            }
            Ok(k) => got += k,
            Err(e) => return Err(e),
        }
    }
    Ok(buf)
}

fn serve_tcp_client(mut sock: TcpStream, peer: String) {
    loop {
        let header = match recv_exactly(&mut sock, 2) {
            Ok(h) if h.len() == 2 => h,
            _ => return,
        };
        let length = u16::from_be_bytes([header[0], header[1]]) as usize;
        let query = match recv_exactly(&mut sock, length) {
            Ok(q) if q.len() == length => q,
            _ => return,
        };

        let desc = describe_query(&query);
        log::info!(target: "freegsm.tcp", "[INTERCEPT] TCP  {desc}  (from {peer})");
        let answer = match doh::resolve(&query) {
            Ok(a) => a,
            Err(e) => {
                log::warn!(target: "freegsm.tcp", "[FAILED]    TCP  {desc}  -> DoH error: {e:#}; closing");
                return;
            }
        };

        log::info!(target: "freegsm.tcp", "[RESOLVED]  TCP  {desc}  -> {} bytes", answer.len());
        let mut framed = Vec::with_capacity(2 + answer.len());
        framed.extend_from_slice(&(answer.len() as u16).to_be_bytes());
        framed.extend_from_slice(&answer);
        if sock.write_all(&framed).is_err() {
            return;
        }
    }
}
