//! netd (Linux prototype): socket-offload network daemon.
//!
//! Guest connections arrive over vsock (either through vhost-device-vsock's
//! hybrid Unix socket or the kernel vhost-vsock device), carry an offload
//! request header and are turned into real host TCP connections. Host port
//! forwards go the opposite way.
//!
//! With `--vhost-user` netd is itself the guest's vhost-user-vsock device and
//! moves payload directly between guest memory and host sockets (see `vu`).

#[cfg(target_os = "linux")]
mod pump;
mod vu;

use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::exit;
use std::sync::Arc;
use std::thread;

use netd_common::proto::{self, Msg, PROTO_TCP, Request};
use netd_common::shm::NO_SLOT;
use netd_common::{relay, sock};

const USAGE: &str = "usage: netd [options]
  --vhost-user PATH        be the guest's vhost-user-vsock device on socket PATH (fastest;
                           QEMU: -chardev socket,path=PATH -device vhost-user-vsock-pci)
  --guest-cid CID          guest CID for --vhost-user (default 3)
  --listen-uds PATH        accept guest connections on a Unix socket (vhost-device-vsock: <uds-path>_<port>)
  --listen-vsock PORT      accept guest connections on AF_VSOCK (kernel vhost-vsock)
  --guest-uds PATH         reach the guest agent through vhost-device-vsock's <uds-path>
  --guest-vsock CID        reach the guest agent through AF_VSOCK
  --guest-port PORT        vsock port of the guest agent's inbound listener (default 1025)
  --forward ADDR=PORT      forward host TCP ADDR (e.g. 127.0.0.1:8080) to guest port PORT
  --host-alias IP          guest-visible address that maps to host loopback (repeatable;
                           default 192.168.5.2 and fd00:5::2)
  --vsock-buf BYTES        vsock credit window for AF_VSOCK sockets (default 4194304)
  --workers N              with --vhost-user: threads moving shared-ring payload (default:
                           CPU count, at most 4)
  --busy-poll-us US        with --vhost-user: keep polling active shared rings this long
                           before sleeping (default 50, 0 = event driven only)";

enum GuestPath {
    Uds(String),
    Vsock(u32),
}

struct Config {
    vhost_user: Option<String>,
    guest_cid: u64,
    listen_uds: Vec<String>,
    listen_vsock: Vec<u32>,
    guest: Option<GuestPath>,
    guest_port: u32,
    forwards: Vec<(SocketAddr, u16)>,
    aliases: Vec<IpAddr>,
    vsock_buf: u64,
    workers: usize,
    busy_poll_us: u64,
}

fn die(m: &str) -> ! {
    eprintln!("netd: {m}\n{USAGE}");
    exit(2)
}

fn parse<T: std::str::FromStr>(v: &str, what: &str) -> T {
    v.parse().unwrap_or_else(|_| die(&format!("bad {what}: {v}")))
}

fn parse_args() -> Config {
    let mut c = Config {
        vhost_user: None,
        guest_cid: 3,
        listen_uds: vec![],
        listen_vsock: vec![],
        guest: None,
        guest_port: 1025,
        forwards: vec![],
        aliases: vec![],
        vsock_buf: 4 << 20,
        workers: std::thread::available_parallelism().map_or(1, |n| n.get().min(4)),
        busy_poll_us: 50,
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "-h" || a == "--help" {
            println!("{USAGE}");
            exit(0)
        }
        let v = args.next().unwrap_or_else(|| die(&format!("{a} needs a value")));
        match a.as_str() {
            "--vhost-user" => c.vhost_user = Some(v),
            "--guest-cid" => c.guest_cid = parse(&v, "cid"),
            "--listen-uds" => c.listen_uds.push(v),
            "--listen-vsock" => c.listen_vsock.push(parse(&v, "port")),
            "--guest-uds" => c.guest = Some(GuestPath::Uds(v)),
            "--guest-vsock" => c.guest = Some(GuestPath::Vsock(parse(&v, "cid"))),
            "--guest-port" => c.guest_port = parse(&v, "port"),
            "--forward" => {
                let (h, g) = v.split_once('=').unwrap_or_else(|| die("--forward wants ADDR=PORT"));
                c.forwards.push((parse(h, "forward address"), parse(g, "forward port")));
            }
            "--host-alias" => c.aliases.push(parse(&v, "alias")),
            "--vsock-buf" => c.vsock_buf = parse(&v, "size"),
            "--workers" => c.workers = parse(&v, "worker count"),
            "--busy-poll-us" => c.busy_poll_us = parse(&v, "microseconds"),
            _ => die(&format!("unknown option {a}")),
        }
    }
    if c.aliases.is_empty() {
        c.aliases = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 5, 2)), IpAddr::V6("fd00:5::2".parse().unwrap())];
    }
    if c.vhost_user.is_some() {
        if !c.listen_uds.is_empty() || !c.listen_vsock.is_empty() || c.guest.is_some() {
            die("--vhost-user cannot be combined with --listen-*/--guest-uds/--guest-vsock");
        }
        return c;
    }
    if c.listen_uds.is_empty() && c.listen_vsock.is_empty() && c.forwards.is_empty() {
        die("nothing to do");
    }
    if !c.forwards.is_empty() && c.guest.is_none() {
        die("--forward needs --guest-uds or --guest-vsock");
    }
    c
}

pub(crate) fn map_dst(aliases: &[IpAddr], dst: SocketAddr) -> SocketAddr {
    if aliases.contains(&dst.ip()) {
        let lo = match dst.ip() {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
        };
        return SocketAddr::new(lo, dst.port());
    }
    dst
}

/// Serve one guest-initiated connection: read the request, connect, relay.
fn serve_outbound(conn: OwnedFd, aliases: &[IpAddr]) -> io::Result<()> {
    let mut f = File::from(conn);
    // Shared-memory rings need guest memory access, which only the
    // vhost-user mode has; payload always goes over the stream here.
    let req = match Msg::read_from(&mut f)? {
        Msg::Connect(r) if r.proto == PROTO_TCP => r,
        _ => return proto::write_error(&mut f, libc::EPROTONOSUPPORT),
    };
    let tcp = match TcpStream::connect(map_dst(aliases, req.dst)) {
        Ok(t) => t,
        Err(e) => return proto::write_error(&mut f, e.raw_os_error().unwrap_or(libc::ECONNREFUSED)),
    };
    tcp.set_nodelay(true)?;
    proto::write_status(&mut f, 0, NO_SLOT)?;
    relay::relay(f.into(), tcp.into());
    Ok(())
}

fn connect_guest(g: &GuestPath, port: u32, vsock_buf: u64) -> io::Result<OwnedFd> {
    match g {
        GuestPath::Vsock(cid) => sock::vsock_connect(*cid, port, Some(vsock_buf)),
        GuestPath::Uds(path) => {
            // vhost-device-vsock hybrid protocol: "CONNECT <port>\n" -> "OK <host_port>\n"
            let mut s = UnixStream::connect(path)?;
            s.write_all(format!("CONNECT {port}\n").as_bytes())?;
            let mut line = Vec::new();
            let mut b = [0u8; 1];
            while b[0] != b'\n' {
                if s.read(&mut b)? == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "guest closed during CONNECT"));
                }
                line.push(b[0]);
            }
            if !line.starts_with(b"OK") {
                return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "guest refused CONNECT"));
            }
            Ok(s.into())
        }
    }
}

/// Serve one host-side forwarded connection into the guest.
fn serve_forward(tcp: TcpStream, cfg: &Config, guest_port: u16) -> io::Result<()> {
    tcp.set_nodelay(true)?;
    let g = cfg.guest.as_ref().expect("checked in parse_args");
    let mut f = File::from(connect_guest(g, cfg.guest_port, cfg.vsock_buf)?);
    let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), guest_port);
    f.write_all(&Request::tcp(dst, NO_SLOT).encode())?;
    match proto::read_status(&mut f)? {
        (0, NO_SLOT) => {}
        (0, _) => return Err(io::Error::new(io::ErrorKind::InvalidData, "guest picked a shared-memory slot")),
        (e, _) => return Err(io::Error::from_raw_os_error(e)),
    }
    relay::relay(f.into(), tcp.into());
    Ok(())
}

fn spawn_acceptor(name: String, listener: OwnedFd, aliases: Arc<Vec<IpAddr>>, vsock_buf: Option<u64>) {
    thread::spawn(move || {
        loop {
            match sock::accept(listener.as_raw_fd()) {
                Ok(c) => {
                    if let Some(b) = vsock_buf {
                        let _ = sock::set_vsock_buffer(c.as_raw_fd(), b);
                    }
                    let aliases = aliases.clone();
                    thread::spawn(move || {
                        if let Err(e) = serve_outbound(c, &aliases) {
                            eprintln!("netd: outbound: {e}");
                        }
                    });
                }
                Err(e) => eprintln!("netd: accept on {name}: {e}"),
            }
        }
    });
}

#[cfg(target_os = "linux")]
fn run_vhost_user(path: &str, cfg: &Config) -> ! {
    let forwards = cfg
        .forwards
        .iter()
        .map(|&(addr, gport)| {
            let l = TcpListener::bind(addr).unwrap_or_else(|e| {
                eprintln!("netd: forward bind {addr}: {e}");
                exit(1)
            });
            l.set_nonblocking(true).expect("nonblocking listener");
            eprintln!("netd: forwarding {addr} -> guest port {gport}");
            (l, gport)
        })
        .collect();
    vu::serve(
        path,
        vu::Config {
            cid: cfg.guest_cid,
            aliases: cfg.aliases.clone(),
            listen_port: 1024,
            guest_port: cfg.guest_port,
            forwards,
            workers: cfg.workers,
            busy_poll: std::time::Duration::from_micros(cfg.busy_poll_us),
        },
    )
}

fn main() {
    let cfg = Arc::new(parse_args());
    if let Some(path) = &cfg.vhost_user {
        #[cfg(target_os = "linux")]
        run_vhost_user(path, &cfg);
        #[cfg(not(target_os = "linux"))]
        die(&format!("--vhost-user {path} is only supported on Linux"));
    }
    let aliases = Arc::new(cfg.aliases.clone());

    for path in &cfg.listen_uds {
        let _ = std::fs::remove_file(path);
        let l = UnixListener::bind(path).unwrap_or_else(|e| {
            eprintln!("netd: bind {path}: {e}");
            exit(1)
        });
        eprintln!("netd: listening for guest connections on {path}");
        spawn_acceptor(path.clone(), l.into(), aliases.clone(), None);
    }
    for &port in &cfg.listen_vsock {
        let l = sock::vsock_listen(port).unwrap_or_else(|e| {
            eprintln!("netd: vsock listen {port}: {e}");
            exit(1)
        });
        eprintln!("netd: listening for guest connections on vsock port {port}");
        spawn_acceptor(format!("vsock:{port}"), l, aliases.clone(), Some(cfg.vsock_buf));
    }
    for &(addr, gport) in &cfg.forwards {
        let l = TcpListener::bind(addr).unwrap_or_else(|e| {
            eprintln!("netd: forward bind {addr}: {e}");
            exit(1)
        });
        eprintln!("netd: forwarding {addr} -> guest port {gport}");
        let cfg = cfg.clone();
        thread::spawn(move || {
            for c in l.incoming() {
                match c {
                    Ok(t) => {
                        let cfg = cfg.clone();
                        thread::spawn(move || {
                            if let Err(e) = serve_forward(t, &cfg, gport) {
                                eprintln!("netd: forward: {e}");
                            }
                        });
                    }
                    Err(e) => eprintln!("netd: forward accept: {e}"),
                }
            }
        });
    }
    loop {
        thread::park();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias_maps_to_loopback() {
        let aliases = vec!["192.168.5.2".parse().unwrap(), "fd00:5::2".parse().unwrap()];
        assert_eq!(map_dst(&aliases, "192.168.5.2:80".parse().unwrap()), "127.0.0.1:80".parse().unwrap());
        assert_eq!(map_dst(&aliases, "[fd00:5::2]:80".parse().unwrap()), "[::1]:80".parse().unwrap());
        assert_eq!(map_dst(&aliases, "1.1.1.1:53".parse().unwrap()), "1.1.1.1:53".parse().unwrap());
    }
}
