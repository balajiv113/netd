//! netd-agent: guest side of the socket-offload path.
//!
//! Outbound: guest TCP connections are redirected (iptables REDIRECT) to the
//! agent's listener. The agent recovers the original destination with
//! SO_ORIGINAL_DST and hands the stream to netd over vsock.
//!
//! Inbound: netd connects to the agent's vsock port for host port forwards;
//! the agent connects to the requested guest-local port.

use std::fs::File;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::exit;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use netd_common::proto::{self, PROTO_TCP, Request};
use netd_common::{relay, sock};

const USAGE: &str = "usage: netd-agent [options]
  --listen ADDR          redirect target for outbound TCP (default 0.0.0.0:15001)
  --vsock CID:PORT       netd endpoint (default 2:1024)
  --unix PATH            use a Unix socket instead of vsock (testing)
  --inbound-vsock PORT   vsock port for host port forwards (default 1025, 0 = off)
  --inbound-unix PATH    Unix socket for host port forwards (testing)
  --fixed-dst ADDR       destination to use when SO_ORIGINAL_DST is unavailable (testing)
  --vsock-buf BYTES      vsock credit window (default 4194304)
  --splice-to-vsock 0|1  splice guest TCP -> vsock (default 1; 0 = plain writes)";

#[derive(Clone)]
enum Upstream {
    Vsock(u32, u32),
    Unix(String),
}

struct Config {
    listen: SocketAddr,
    upstream: Upstream,
    inbound_vsock: u32,
    inbound_unix: Option<String>,
    fixed_dst: Option<SocketAddr>,
    vsock_buf: u64,
}

static SPLICE_TO_VSOCK: AtomicBool = AtomicBool::new(true);

fn die(m: &str) -> ! {
    eprintln!("netd-agent: {m}\n{USAGE}");
    exit(2)
}

fn parse<T: std::str::FromStr>(v: &str, what: &str) -> T {
    v.parse().unwrap_or_else(|_| die(&format!("bad {what}: {v}")))
}

fn parse_args() -> Config {
    let mut c = Config {
        listen: "0.0.0.0:15001".parse().unwrap(),
        upstream: Upstream::Vsock(sock::VMADDR_CID_HOST, 1024),
        inbound_vsock: 1025,
        inbound_unix: None,
        fixed_dst: None,
        vsock_buf: 4 << 20,
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "-h" || a == "--help" {
            println!("{USAGE}");
            exit(0)
        }
        let v = args.next().unwrap_or_else(|| die(&format!("{a} needs a value")));
        match a.as_str() {
            "--listen" => c.listen = parse(&v, "address"),
            "--vsock" => {
                let (cid, port) = v.split_once(':').unwrap_or_else(|| die("--vsock wants CID:PORT"));
                c.upstream = Upstream::Vsock(parse(cid, "cid"), parse(port, "port"));
            }
            "--unix" => c.upstream = Upstream::Unix(v),
            "--inbound-vsock" => c.inbound_vsock = parse(&v, "port"),
            "--inbound-unix" => c.inbound_unix = Some(v),
            "--fixed-dst" => c.fixed_dst = Some(parse(&v, "address")),
            "--vsock-buf" => c.vsock_buf = parse(&v, "size"),
            "--splice-to-vsock" => SPLICE_TO_VSOCK.store(v == "1", Ordering::Relaxed),
            _ => die(&format!("unknown option {a}")),
        }
    }
    c
}

/// Destination the guest application originally connected to, before the
/// netfilter REDIRECT rewrote it.
fn original_dst(fd: RawFd, v6: bool) -> io::Result<SocketAddr> {
    const SO_ORIGINAL_DST: libc::c_int = 80;
    unsafe {
        if v6 {
            let mut a: libc::sockaddr_in6 = std::mem::zeroed();
            let mut len = size_of::<libc::sockaddr_in6>() as libc::socklen_t;
            if libc::getsockopt(fd, libc::SOL_IPV6, SO_ORIGINAL_DST, (&mut a as *mut libc::sockaddr_in6).cast(), &mut len) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(a.sin6_addr.s6_addr)), u16::from_be(a.sin6_port)))
        } else {
            let mut a: libc::sockaddr_in = std::mem::zeroed();
            let mut len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
            if libc::getsockopt(fd, libc::SOL_IP, SO_ORIGINAL_DST, (&mut a as *mut libc::sockaddr_in).cast(), &mut len) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr))), u16::from_be(a.sin_port)))
        }
    }
}

fn connect_upstream(u: &Upstream, vsock_buf: u64) -> io::Result<OwnedFd> {
    match u {
        Upstream::Vsock(cid, port) => sock::vsock_connect(*cid, *port, Some(vsock_buf)),
        Upstream::Unix(p) => Ok(UnixStream::connect(p)?.into()),
    }
}

fn serve_outbound(tcp: TcpStream, cfg: &Config) -> io::Result<()> {
    tcp.set_nodelay(true)?;
    let dst = match cfg.fixed_dst {
        Some(d) => d,
        None => original_dst(tcp.as_raw_fd(), tcp.local_addr()?.is_ipv6())?,
    };
    let mut up = File::from(connect_upstream(&cfg.upstream, cfg.vsock_buf)?);
    up.write_all(&Request::tcp(dst).encode())?;
    let st = proto::read_status(&mut up)?;
    if st != 0 {
        // Close the guest connection; the app sees a reset/EOF.
        return Err(io::Error::from_raw_os_error(st));
    }
    relay::relay_dirs(tcp.into(), up.into(), SPLICE_TO_VSOCK.load(Ordering::Relaxed), true);
    Ok(())
}

fn serve_inbound(conn: OwnedFd) -> io::Result<()> {
    let mut f = File::from(conn);
    let req = Request::read_from(&mut f)?;
    if req.proto != PROTO_TCP || !req.dst.ip().is_loopback() {
        return proto::write_status(&mut f, libc::EPERM);
    }
    let tcp = match TcpStream::connect(req.dst) {
        Ok(t) => t,
        Err(e) => return proto::write_status(&mut f, e.raw_os_error().unwrap_or(libc::ECONNREFUSED)),
    };
    tcp.set_nodelay(true)?;
    proto::write_status(&mut f, 0)?;
    relay::relay_dirs(f.into(), tcp.into(), true, SPLICE_TO_VSOCK.load(Ordering::Relaxed));
    Ok(())
}

fn spawn_inbound(listener: OwnedFd, vsock_buf: Option<u64>) {
    thread::spawn(move || {
        loop {
            match sock::accept(listener.as_raw_fd()) {
                Ok(c) => {
                    if let Some(b) = vsock_buf {
                        let _ = sock::set_vsock_buffer(c.as_raw_fd(), b);
                    }
                    thread::spawn(move || {
                        if let Err(e) = serve_inbound(c) {
                            eprintln!("netd-agent: inbound: {e}");
                        }
                    });
                }
                Err(e) => eprintln!("netd-agent: inbound accept: {e}"),
            }
        }
    });
}

fn main() {
    let cfg = Arc::new(parse_args());

    if let Some(p) = &cfg.inbound_unix {
        let _ = std::fs::remove_file(p);
        let l = UnixListener::bind(p).unwrap_or_else(|e| die(&format!("bind {p}: {e}")));
        spawn_inbound(l.into(), None);
    } else if cfg.inbound_vsock != 0 {
        match sock::vsock_listen(cfg.inbound_vsock) {
            Ok(l) => spawn_inbound(l, Some(cfg.vsock_buf)),
            Err(e) => eprintln!("netd-agent: inbound vsock {}: {e} (port forwards disabled)", cfg.inbound_vsock),
        }
    }

    let l = TcpListener::bind(cfg.listen).unwrap_or_else(|e| die(&format!("bind {}: {e}", cfg.listen)));
    eprintln!("netd-agent: redirect target {}", cfg.listen);
    for c in l.incoming() {
        match c {
            Ok(t) => {
                let cfg = cfg.clone();
                thread::spawn(move || {
                    if let Err(e) = serve_outbound(t, &cfg) {
                        eprintln!("netd-agent: outbound: {e}");
                    }
                });
            }
            Err(e) => eprintln!("netd-agent: accept: {e}"),
        }
    }
}
