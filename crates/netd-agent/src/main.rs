//! netd-agent: guest side of the socket-offload path.
//!
//! Outbound: guest TCP connections are redirected (iptables REDIRECT) to the
//! agent's listener. The agent recovers the original destination with
//! SO_ORIGINAL_DST and hands the stream to netd over vsock.
//!
//! Inbound: netd connects to the agent's vsock port for host port forwards;
//! the agent connects to the requested guest-local port.
//!
//! With netd's vhost-user device, connections carry their payload through
//! shared rings in guest hugepages (see `shm`) instead of the vsock stream.

mod acceptor;
mod pool;
mod shm;

use std::fs::File;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::exit;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use netd_common::proto::{self, Msg, PROTO_TCP, Request};
use netd_common::shm::{MAX_SLOTS, NO_SLOT};
use netd_common::{relay, sock};
use pool::Pool;

const USAGE: &str = "usage: netd-agent [options]
  --listen ADDR          redirect target for outbound TCP (default 0.0.0.0:15001);
                         may be repeated
  --vsock CID:PORT       netd endpoint (default 2:1024)
  --unix PATH            use a Unix socket instead of vsock (testing)
  --inbound-vsock PORT   vsock port for host port forwards (default 1025, 0 = off)
  --inbound-unix PATH    Unix socket for host port forwards (testing)
  --fixed-dst ADDR       destination for the preceding --listen instead of
                         SO_ORIGINAL_DST (testing)
  --shm-slots N          shared-ring slots, i.e. concurrent connections using
                         shared memory (default 16, 0 = off)
  --spin-us US           busy-poll the shared rings this long before sleeping
                         (default 50, outbound startup 200; 0 = off)
  --pool N               pre-connected netd streams kept for new outbound
                         connections (default 4, 0 = connect on demand)
  --vsock-buf BYTES      vsock credit window (default 4194304)
  --splice-to-vsock 0|1  splice guest TCP -> vsock (default 1; 0 = plain writes)";

#[derive(Clone)]
enum Upstream {
    Vsock(u32, u32),
    Unix(String),
}

struct Listen {
    addr: SocketAddr,
    fixed_dst: Option<SocketAddr>,
}

struct Config {
    listens: Vec<Listen>,
    upstream: Upstream,
    inbound_vsock: u32,
    inbound_unix: Option<String>,
    vsock_buf: u64,
    shm_slots: usize,
    pool_size: usize,
    region: Option<Arc<shm::Region>>,
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
        listens: Vec::new(),
        upstream: Upstream::Vsock(sock::VMADDR_CID_HOST, 1024),
        inbound_vsock: 1025,
        inbound_unix: None,
        vsock_buf: 4 << 20,
        shm_slots: 16,
        pool_size: 4,
        region: None,
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "-h" || a == "--help" {
            println!("{USAGE}");
            exit(0)
        }
        let v = args.next().unwrap_or_else(|| die(&format!("{a} needs a value")));
        match a.as_str() {
            "--listen" => c.listens.push(Listen { addr: parse(&v, "address"), fixed_dst: None }),
            "--vsock" => {
                let (cid, port) = v.split_once(':').unwrap_or_else(|| die("--vsock wants CID:PORT"));
                c.upstream = Upstream::Vsock(parse(cid, "cid"), parse(port, "port"));
            }
            "--unix" => c.upstream = Upstream::Unix(v),
            "--inbound-vsock" => c.inbound_vsock = parse(&v, "port"),
            "--inbound-unix" => c.inbound_unix = Some(v),
            "--fixed-dst" => {
                let l = c.listens.last_mut().unwrap_or_else(|| die("--fixed-dst must follow a --listen"));
                l.fixed_dst = Some(parse(&v, "address"));
            }
            "--shm-slots" => {
                c.shm_slots = parse(&v, "slot count");
                if c.shm_slots > MAX_SLOTS {
                    die(&format!("--shm-slots is at most {MAX_SLOTS}"));
                }
            }
            "--pool" => c.pool_size = parse(&v, "pool size"),
            "--vsock-buf" => c.vsock_buf = parse(&v, "size"),
            "--spin-us" => shm::set_spin_us(parse(&v, "microseconds")),
            "--splice-to-vsock" => SPLICE_TO_VSOCK.store(v == "1", Ordering::Relaxed),
            _ => die(&format!("unknown option {a}")),
        }
    }
    if c.listens.is_empty() {
        c.listens.push(Listen { addr: "0.0.0.0:15001".parse().unwrap(), fixed_dst: None });
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

fn serve_outbound(tcp: TcpStream, fixed_dst: Option<SocketAddr>, cfg: &Config, pool: &Pool) -> io::Result<()> {
    tcp.set_nodelay(true)?;
    let dst = match fixed_dst {
        Some(d) => d,
        None => original_dst(tcp.as_raw_fd(), tcp.local_addr()?.is_ipv6())?,
    };
    if let Some(slot) = cfg.region.as_ref().and_then(|r| r.claim()) {
        return shm::relay_out(tcp.into(), slot, dst);
    }
    let mut up = File::from(pool.take()?);
    up.write_all(&Request::tcp(dst, NO_SLOT).encode())?;
    let (st, got) = proto::read_status(&mut up)?;
    if st != 0 {
        // Close the guest connection; the app sees a reset/EOF.
        return Err(io::Error::from_raw_os_error(st));
    }
    if got != NO_SLOT {
        return Err(io::Error::other("netd assigned a slot that was not offered"));
    }
    relay::relay_dirs(tcp.into(), up.into(), SPLICE_TO_VSOCK.load(Ordering::Relaxed), true);
    Ok(())
}

fn serve_inbound(conn: OwnedFd, region: &Option<Arc<shm::Region>>) -> io::Result<()> {
    let mut f = File::from(conn);
    let req = match Msg::read_from(&mut f)? {
        Msg::Connect(r) if r.proto == PROTO_TCP && r.dst.ip().is_loopback() => r,
        _ => return proto::write_error(&mut f, libc::EPERM),
    };
    let tcp = match TcpStream::connect(req.dst) {
        Ok(t) => t,
        Err(e) => return proto::write_error(&mut f, e.raw_os_error().unwrap_or(libc::ECONNREFUSED)),
    };
    tcp.set_nodelay(true)?;
    // Only netd's vhost-user device can use the rings; it marks that by
    // leaving the slot choice to the agent (thread mode never sees a slot).
    let (slot, idx) = shm::offer(region);
    proto::write_status(&mut f, 0, idx)?;
    match slot {
        Some(s) => shm::relay_in(tcp.into(), f.into(), s),
        None => {
            relay::relay_dirs(f.into(), tcp.into(), true, SPLICE_TO_VSOCK.load(Ordering::Relaxed));
            Ok(())
        }
    }
}

fn spawn_inbound(listener: OwnedFd, vsock_buf: Option<u64>, region: Option<Arc<shm::Region>>) {
    acceptor::spawn(
        move || sock::accept(listener.as_raw_fd()),
        move |c| {
            if let Some(b) = vsock_buf {
                let _ = sock::set_vsock_buffer(c.as_raw_fd(), b);
            }
            if let Err(e) = serve_inbound(c, &region) {
                eprintln!("netd-agent: inbound: {e}");
            }
        },
    );
}

fn main() {
    let mut cfg = parse_args();

    if cfg.shm_slots > 0 {
        match shm::Region::new(cfg.shm_slots) {
            Ok(r) => {
                let r = Arc::new(r);
                let (up, buf) = (cfg.upstream.clone(), cfg.vsock_buf);
                r.register(move || connect_upstream(&up, buf));
                cfg.region = Some(r);
            }
            Err(e) => eprintln!("netd-agent: shared rings unavailable: {e}"),
        }
    }

    if let Some(p) = &cfg.inbound_unix {
        let _ = std::fs::remove_file(p);
        let l = UnixListener::bind(p).unwrap_or_else(|e| die(&format!("bind {p}: {e}")));
        spawn_inbound(l.into(), None, cfg.region.clone());
    } else if cfg.inbound_vsock != 0 {
        match sock::vsock_listen(cfg.inbound_vsock) {
            Ok(l) => spawn_inbound(l, Some(cfg.vsock_buf), cfg.region.clone()),
            Err(e) => eprintln!("netd-agent: inbound vsock {}: {e} (port forwards disabled)", cfg.inbound_vsock),
        }
    }

    let listeners: Vec<(TcpListener, Option<SocketAddr>)> = cfg
        .listens
        .iter()
        .map(|l| {
            let t = TcpListener::bind(l.addr).unwrap_or_else(|e| die(&format!("bind {}: {e}", l.addr)));
            eprintln!("netd-agent: redirect target {}", l.addr);
            (t, l.fixed_dst)
        })
        .collect();
    let (up, buf) = (cfg.upstream.clone(), cfg.vsock_buf);
    let pool = Pool::new(cfg.pool_size, Box::new(move || connect_upstream(&up, buf)));
    let cfg = Arc::new(cfg);
    for (l, fixed_dst) in listeners {
        let (cfg, pool) = (cfg.clone(), pool.clone());
        acceptor::spawn(
            move || l.accept().map(|(t, _)| t),
            move |t| {
                if let Err(e) = serve_outbound(t, fixed_dst, &cfg, &pool) {
                    eprintln!("netd-agent: outbound: {e}");
                }
            },
        );
    }
    loop {
        thread::park();
    }
}
