//! Embedded vhost-user-vsock device.
//!
//! QEMU connects to a vhost-user socket and shares guest memory with netd,
//! so netd parses guest vsock packets itself:
//!
//! * guest -> host: payload is written from guest memory straight into the
//!   host TCP socket with writev (no bounce buffer unless the socket is full);
//! * host -> guest: one readv fills a whole batch of guest RX buffers.
//!
//! This removes the separate vhost-device-vsock process, its Unix socket hop
//! and its per-packet copies. Everything runs on the backend's worker thread.
//!
//! When the agent has registered shared rings (netd_common::shm), connections
//! that hold a slot bypass vsock packets entirely: netd moves payload between
//! the host socket and the rings in guest memory. Outbound connections run on
//! the slot's long-lived stream, which only carries proto::Frame messages;
//! port forwards keep a stream each, carrying the handshake and doorbells.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use netd_common::proto::{self, Frame, FrameReader, Msg, PROTO_TCP, Request, STATUS_LEN, ShmRegion};
use netd_common::shm::{CHUNK, Consumer, NO_SLOT, Producer, RING_SIZE, Ring, SLOT_CTL, SlotCtl};
use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost_user_backend::{VhostUserBackend, VhostUserDaemon, VringRwLock, VringState, VringT};
use virtio_bindings::bindings::virtio_config::VIRTIO_F_VERSION_1;
use virtio_bindings::bindings::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use virtio_queue::desc::split::Descriptor;
use virtio_queue::{QueueOwnedT, QueueT};
use vm_memory::{GuestAddress, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryBackend, GuestMemoryMmap};
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::event::{EventConsumer, EventFlag, EventNotifier, new_event_consumer_and_notifier};

const NUM_QUEUES: usize = 3;
const RXQ: usize = 0;
const TXQ: usize = 1;
const EVQ: u16 = 2;
/// Listener id for netd's own epoll fd (0..=NUM_QUEUES are reserved).
const EPOLL_EVENT: u16 = NUM_QUEUES as u16 + 1;

const HOST_CID: u64 = 2;
const HDR: usize = 44;
const TYPE_STREAM: u16 = 1;
const OP_REQUEST: u16 = 1;
const OP_RESPONSE: u16 = 2;
const OP_RST: u16 = 3;
const OP_SHUTDOWN: u16 = 4;
const OP_RW: u16 = 5;
const OP_CREDIT_UPDATE: u16 = 6;
const OP_CREDIT_REQUEST: u16 = 7;
const SHUT_RCV: u32 = 1;
const SHUT_SEND: u32 = 2;

/// Receive window advertised to the guest per connection.
const BUF_ALLOC: u32 = 4 << 20;
/// Upper bound of host->guest bytes moved by one readv.
const RX_BATCH: usize = 1 << 20;
const LISTENER_BIT: u64 = 1 << 63;
/// epoll token of the eventfd the worker uses to reschedule itself.
const YIELD_TOK: u64 = 0;
/// Longest stretch the worker busy-polls before letting other users of the
/// device lock (e.g. the vhost-user frontend thread) in.
const MAX_POLL: Duration = Duration::from_millis(1);
/// Host-side vsock ports for forwarded connections are allocated from here.
const FIRST_HOST_PORT: u32 = 0x4000_0000;

pub struct Config {
    pub cid: u64,
    pub aliases: Vec<IpAddr>,
    /// Port the guest agent connects to for outbound offload.
    pub listen_port: u32,
    /// Guest agent port for host port forwards.
    pub guest_port: u32,
    /// Non-blocking TCP listeners and the guest port each forwards to.
    pub forwards: Vec<(TcpListener, u16)>,
    /// How long the worker keeps polling shared rings after the last work
    /// before it sleeps (zero = event driven only).
    pub busy_poll: Duration,
}

#[derive(Default, Clone, Copy, Debug, PartialEq)]
struct Hdr {
    src_cid: u64,
    dst_cid: u64,
    src_port: u32,
    dst_port: u32,
    len: u32,
    typ: u16,
    op: u16,
    flags: u32,
    buf_alloc: u32,
    fwd_cnt: u32,
}

impl Hdr {
    fn parse(b: &[u8; HDR]) -> Self {
        let u64_at = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        let u32_at = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        let u16_at = |o: usize| u16::from_le_bytes(b[o..o + 2].try_into().unwrap());
        Hdr {
            src_cid: u64_at(0),
            dst_cid: u64_at(8),
            src_port: u32_at(16),
            dst_port: u32_at(20),
            len: u32_at(24),
            typ: u16_at(28),
            op: u16_at(30),
            flags: u32_at(32),
            buf_alloc: u32_at(36),
            fwd_cnt: u32_at(40),
        }
    }

    fn encode(&self) -> [u8; HDR] {
        let mut b = [0u8; HDR];
        b[0..8].copy_from_slice(&self.src_cid.to_le_bytes());
        b[8..16].copy_from_slice(&self.dst_cid.to_le_bytes());
        b[16..20].copy_from_slice(&self.src_port.to_le_bytes());
        b[20..24].copy_from_slice(&self.dst_port.to_le_bytes());
        b[24..28].copy_from_slice(&self.len.to_le_bytes());
        b[28..30].copy_from_slice(&self.typ.to_le_bytes());
        b[30..32].copy_from_slice(&self.op.to_le_bytes());
        b[32..36].copy_from_slice(&self.flags.to_le_bytes());
        b[36..40].copy_from_slice(&self.buf_alloc.to_le_bytes());
        b[40..44].copy_from_slice(&self.fwd_cnt.to_le_bytes());
        b
    }
}

/// A contiguous piece of guest memory mapped into netd.
#[derive(Clone, Copy)]
struct Seg {
    ptr: *mut u8,
    len: usize,
}

fn segs_len(segs: &[Seg]) -> usize {
    segs.iter().map(|s| s.len).sum()
}

/// Calls `f(ptr, len)` for every piece of `segs` in the byte range `off..off+len`.
fn segs_range(segs: &[Seg], mut off: usize, mut len: usize, mut f: impl FnMut(*mut u8, usize)) {
    for s in segs {
        if len == 0 {
            break;
        }
        if off >= s.len {
            off -= s.len;
            continue;
        }
        let n = (s.len - off).min(len);
        // SAFETY: off < s.len, so the pointer stays inside the mapped segment.
        f(unsafe { s.ptr.add(off) }, n);
        off = 0;
        len -= n;
    }
}

fn segs_read(segs: &[Seg], off: usize, out: &mut [u8]) {
    let mut o = 0;
    segs_range(segs, off, out.len(), |p, n| {
        // SAFETY: p..p+n is guest memory mapped for the lifetime of the memory guard.
        unsafe { std::ptr::copy_nonoverlapping(p, out[o..].as_mut_ptr(), n) };
        o += n;
    });
}

fn segs_write(segs: &[Seg], off: usize, data: &[u8]) {
    let mut o = 0;
    segs_range(segs, off, data.len(), |p, n| {
        // SAFETY: as in segs_read; the descriptor is device-writable.
        unsafe { std::ptr::copy_nonoverlapping(data[o..].as_ptr(), p, n) };
        o += n;
    });
}

fn segs_iov(segs: &[Seg], off: usize, len: usize, iov: &mut Vec<libc::iovec>) {
    segs_range(segs, off, len, |p, n| iov.push(libc::iovec { iov_base: p.cast(), iov_len: n }));
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    /// Guest-initiated: reading the offload request header.
    ReadReq,
    /// Guest-initiated: non-blocking TCP connect in progress.
    Connecting,
    /// Host-initiated (port forward): waiting for the guest's RESPONSE.
    AwaitResponse,
    /// Host-initiated: waiting for the guest agent's 4-byte status.
    AwaitStatus,
    /// Connected; relaying payload both ways.
    Relay,
    /// Setup failed; waiting for the guest to close after it read the status.
    Failed,
    /// The agent's shared-ring registration stream; carries no payload.
    Registration,
    /// A slot stream between two connections.
    SlotIdle,
}

/// The agent's registered rings. The memory snapshot keeps the mappings
/// alive; the pointers are validated against it at registration.
struct ShmTable {
    _mem: Arc<Mem>,
    ctl: *mut u8,
    rings: Vec<*mut u8>,
    in_use: Vec<bool>,
    /// The slot has its stream.
    bound: Vec<bool>,
}

/// A connection's rings: netd consumes guest->host and produces host->guest.
struct ShmConn {
    slot: u16,
    ctl: *const SlotCtl,
    tx: Consumer,
    rx: Producer,
}

struct Conn {
    local_port: u32,
    peer_port: u32,
    sock: Option<OwnedFd>,
    state: State,
    /// Handshake bytes from the guest (request header or status).
    hs: Vec<u8>,
    /// Guest payload not yet accepted by the host socket.
    txq: VecDeque<u8>,
    /// In-band bytes for the guest (request header or status) sent before socket data.
    prefix: Vec<u8>,
    /// Bytes received from the guest / freed from our receive window.
    rx_cnt: u32,
    fwd_cnt: u32,
    last_fwd_sent: u32,
    credit_queued: bool,
    /// Bytes sent to the guest and the guest's advertised window.
    tx_cnt: u32,
    peer_buf_alloc: u32,
    peer_fwd_cnt: u32,
    readable: bool,
    writable: bool,
    sock_eof: bool,
    wr_shut: bool,
    guest_shut_send: bool,
    guest_shut_rcv: bool,
    /// A slot stream: its slot, the current connection's id, whether the
    /// agent has finished that connection (Close), and partial frames.
    bound: Option<u16>,
    conn_id: u32,
    guest_done: bool,
    frames: FrameReader,
    shm: Option<ShmConn>,
    /// The last pump stopped at a full ring or socket (see pump_shm).
    bulk: bool,
}

impl Conn {
    fn new(local_port: u32, peer_port: u32, state: State) -> Self {
        Conn {
            local_port,
            peer_port,
            sock: None,
            state,
            hs: Vec::new(),
            txq: VecDeque::new(),
            prefix: Vec::new(),
            rx_cnt: 0,
            fwd_cnt: 0,
            last_fwd_sent: 0,
            credit_queued: false,
            tx_cnt: 0,
            peer_buf_alloc: 0,
            peer_fwd_cnt: 0,
            readable: false,
            writable: false,
            sock_eof: false,
            wr_shut: false,
            guest_shut_send: false,
            guest_shut_rcv: false,
            bound: None,
            conn_id: 0,
            guest_done: false,
            frames: FrameReader::default(),
            shm: None,
            bulk: false,
        }
    }

    /// Forgets the host connection of a slot stream, keeping the stream.
    fn clear_conn(&mut self) {
        self.sock = None;
        self.state = State::SlotIdle;
        self.txq.clear();
        self.readable = false;
        self.writable = false;
        self.sock_eof = false;
        self.wr_shut = false;
        self.guest_done = false;
        self.bulk = false;
    }

    fn peer_credit(&self) -> usize {
        let inflight = self.tx_cnt.wrapping_sub(self.peer_fwd_cnt);
        self.peer_buf_alloc.saturating_sub(inflight) as usize
    }

    /// Moves payload between the host socket and the shared rings until
    /// both directions block. With `arm`, it then asks the agent for
    /// doorbells where a ring is the obstacle. Returns true, possibly with
    /// work left, as soon as the agent must be woken: the caller sends the
    /// doorbell and pumps again, so both sides work on the ring at once.
    fn pump_shm(&mut self, stats: &mut Stats, arm: bool) -> io::Result<bool> {
        let Some(s) = self.shm.as_mut() else { return Ok(false) };
        let fd = self.sock.as_ref().unwrap().as_raw_fd();
        let mut iov = [libc::iovec { iov_base: std::ptr::null_mut(), iov_len: 0 }; 2];
        loop {
            while self.writable && !self.wr_shut {
                let (k, n) = s.tx.data_iov(&mut iov, CHUNK)?;
                if n == 0 {
                    if s.tx.finished()? {
                        unsafe { libc::shutdown(fd, libc::SHUT_WR) };
                        self.wr_shut = true;
                    }
                    break;
                }
                let w = unsafe { libc::writev(fd, iov.as_ptr(), k as i32) };
                if w < 0 {
                    match errno() {
                        libc::EINTR => continue,
                        libc::EAGAIN => {
                            stats.shm_tx_sock_full += 1;
                            self.writable = false;
                        }
                        e => return Err(io::Error::from_raw_os_error(e)),
                    }
                    break;
                }
                stats.shm_tx_bytes += w as u64;
                stats.shm_tx_writes += 1;
                if (w as usize) < n {
                    stats.shm_tx_sock_full += 1;
                    self.writable = false;
                }
                if s.tx.consume(w as usize) {
                    return Ok(true);
                }
            }
            while self.readable && !self.sock_eof && !self.guest_shut_rcv {
                let (k, n) = s.rx.free_iov(&mut iov, CHUNK)?;
                if n == 0 {
                    stats.shm_rx_ring_full += 1;
                    break;
                }
                let r = unsafe { libc::readv(fd, iov.as_ptr(), k as i32) };
                if r < 0 {
                    match errno() {
                        libc::EINTR => continue,
                        libc::EAGAIN => self.readable = false,
                        e => return Err(io::Error::from_raw_os_error(e)),
                    }
                    break;
                }
                if r == 0 {
                    self.sock_eof = true;
                    if s.rx.close() {
                        return Ok(true);
                    }
                    break;
                }
                stats.shm_rx_bytes += r as u64;
                stats.shm_rx_reads += 1;
                if (r as usize) < n {
                    self.readable = false;
                }
                if s.rx.commit(r as usize) {
                    return Ok(true);
                }
            }
            // Blocked by a full ring or a full socket: a bulk transfer, where
            // busy-polling would only take CPU from whoever has to make room.
            let ring_full = self.readable && !self.sock_eof && !self.guest_shut_rcv;
            let sock_full = !self.writable && !self.wr_shut && s.tx.avail()? > 0;
            self.bulk = ring_full || sock_full;
            if !arm && !self.bulk {
                return Ok(false);
            }
            // Out of ring data (or space) with the socket still ready: ask the
            // agent for a doorbell, unless it raced us and there is work again.
            let mut again = false;
            if self.writable && !self.wr_shut && !s.tx.wait()? {
                again = true;
            }
            if self.readable && !self.sock_eof && !self.guest_shut_rcv && !s.rx.wait()? {
                again = true;
            }
            if !again {
                return Ok(false);
            }
        }
    }
}

/// A packet without payload queued for the guest.
struct Ctl {
    local_port: u32,
    peer_port: u32,
    op: u16,
    flags: u32,
}

enum Rx {
    /// Nothing to send until a socket, credit or queue event.
    Idle,
    /// Sent something; may have more.
    Sent,
    /// The RX queue has no free buffers.
    Starved,
}

/// Counters printed every second when NETD_STATS is set.
#[derive(Default, Debug)]
struct Stats {
    wakeups: u64,
    tx_pkts: u64,
    tx_bytes: u64,
    tx_buffered: u64,
    rx_readv: u64,
    rx_chains: u64,
    rx_bytes: u64,
    rx_starved: u64,
    ctl_pkts: u64,
    credit_updates: u64,
    tx_irqs: u64,
    rx_irqs: u64,
    shm_tx_bytes: u64,
    shm_rx_bytes: u64,
    /// writev calls to host sockets, and how often one ended short or EAGAIN.
    shm_tx_writes: u64,
    shm_tx_sock_full: u64,
    /// readv calls from host sockets, and how often the ring had no room.
    shm_rx_reads: u64,
    shm_rx_ring_full: u64,
    bells_in: u64,
    bells_out: u64,
    epoll_events: u64,
    busy_polls: u64,
}

impl Stats {
    /// Changes whenever a processing pass did something.
    fn work(&self) -> u64 {
        self.tx_pkts + self.rx_chains + self.shm_tx_bytes + self.shm_rx_bytes + self.epoll_events + self.bells_out
    }
}

struct Dev {
    stats: Stats,
    stats_at: Option<Instant>,
    cid: u64,
    aliases: Vec<IpAddr>,
    listen_port: u32,
    guest_port: u32,
    forwards: Arc<Vec<(TcpListener, u16)>>,
    mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    event_idx: bool,
    epoll: OwnedFd,
    conns: HashMap<u64, Conn>,
    ports: HashMap<(u32, u32), u64>,
    next_tok: u64,
    next_port: u32,
    ctl: VecDeque<Ctl>,
    rx_ready: HashSet<u64>,
    tx_ready: HashSet<u64>,
    shm_ready: HashSet<u64>,
    shm_toks: Vec<u64>,
    shm: Option<ShmTable>,
    busy_poll: Duration,
    yield_fd: OwnedFd,
    segs: Vec<Seg>,
    iov: Vec<libc::iovec>,
}

// SAFETY: raw pointers in the scratch vectors are only valid during one
// processing pass and are never shared; Dev is always used behind a Mutex.
unsafe impl Send for Dev {}

fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO)
}

fn epoll_add(ep: RawFd, fd: RawFd, events: u32, tok: u64) -> io::Result<()> {
    let mut ev = libc::epoll_event { events, u64: tok };
    if unsafe { libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, fd, &mut ev) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

const SOCK_EVENTS: u32 = (libc::EPOLLIN | libc::EPOLLOUT | libc::EPOLLRDHUP | libc::EPOLLET) as u32;

fn set_nodelay(fd: RawFd) {
    let one: libc::c_int = 1;
    unsafe {
        libc::setsockopt(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY, (&one as *const libc::c_int).cast(), 4);
    }
}

/// Starts a non-blocking TCP connect. Returns the socket and whether the
/// connect is still in progress.
fn connect_nb(dst: SocketAddr) -> io::Result<(OwnedFd, bool)> {
    let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let (dom, len) = match dst {
        SocketAddr::V4(a) => {
            let sin = (&mut ss as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in>();
            unsafe {
                (*sin).sin_family = libc::AF_INET as libc::sa_family_t;
                (*sin).sin_port = a.port().to_be();
                (*sin).sin_addr.s_addr = u32::from_ne_bytes(a.ip().octets());
            }
            (libc::AF_INET, size_of::<libc::sockaddr_in>())
        }
        SocketAddr::V6(a) => {
            let sin6 = (&mut ss as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in6>();
            unsafe {
                (*sin6).sin6_family = libc::AF_INET6 as libc::sa_family_t;
                (*sin6).sin6_port = a.port().to_be();
                (*sin6).sin6_addr.s6_addr = a.ip().octets();
                (*sin6).sin6_scope_id = a.scope_id();
            }
            (libc::AF_INET6, size_of::<libc::sockaddr_in6>())
        }
    };
    let fd = unsafe { libc::socket(dom, libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    set_nodelay(fd.as_raw_fd());
    let r = unsafe { libc::connect(fd.as_raw_fd(), (&ss as *const libc::sockaddr_storage).cast(), len as u32) };
    if r == 0 {
        return Ok((fd, false));
    }
    match errno() {
        libc::EINPROGRESS => Ok((fd, true)),
        e => Err(io::Error::from_raw_os_error(e)),
    }
}

fn so_error(fd: RawFd) -> i32 {
    let mut e: libc::c_int = 0;
    let mut l = size_of::<libc::c_int>() as libc::socklen_t;
    if unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_ERROR, (&mut e as *mut libc::c_int).cast(), &mut l) } < 0 {
        return errno();
    }
    e
}

type Mem = GuestMemoryMmap;

/// Maps the descriptors of one chain. `writable` selects RX (device-writable)
/// or TX (device-readable) chains; mismatching descriptors invalidate it.
fn map_chain<I>(mem: &Mem, chain: I, writable: bool, out: &mut Vec<Seg>) -> bool
where
    I: Iterator<Item = Descriptor>,
{
    for d in chain {
        if d.is_write_only() != writable {
            return false;
        }
        if d.len() == 0 {
            continue;
        }
        let Ok(s) = mem.get_slice(d.addr(), d.len() as usize) else {
            return false;
        };
        out.push(Seg { ptr: s.ptr_guard_mut().as_ptr(), len: d.len() as usize });
    }
    true
}

type VState<'a> = std::sync::RwLockWriteGuard<'a, VringState<GuestMemoryAtomic<Mem>>>;

/// Pops the next available chain, appending its segments to `segs`.
fn pop_chain(st: &mut VState, mem: &Mem, writable: bool, segs: &mut Vec<Seg>) -> Option<u16> {
    loop {
        let chain = match st.get_queue_mut().iter(mem) {
            Ok(mut it) => it.next()?,
            Err(e) => {
                eprintln!("netd: vhost-user: queue error: {e}");
                return None;
            }
        };
        let head = chain.head_index();
        let start = segs.len();
        if map_chain(mem, chain, writable, segs) {
            return Some(head);
        }
        eprintln!("netd: vhost-user: dropping malformed descriptor chain");
        segs.truncate(start);
        let _ = st.add_used(head, 0);
    }
}

impl Dev {
    fn new(cfg: &Config, forwards: Arc<Vec<(TcpListener, u16)>>) -> io::Result<Self> {
        let ep = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if ep < 0 {
            return Err(io::Error::last_os_error());
        }
        let epoll = unsafe { OwnedFd::from_raw_fd(ep) };
        for (i, (l, _)) in forwards.iter().enumerate() {
            epoll_add(ep, l.as_raw_fd(), libc::EPOLLIN as u32, LISTENER_BIT | i as u64)?;
        }
        let efd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        if efd < 0 {
            return Err(io::Error::last_os_error());
        }
        let yield_fd = unsafe { OwnedFd::from_raw_fd(efd) };
        epoll_add(ep, efd, libc::EPOLLIN as u32, YIELD_TOK)?;
        Ok(Dev {
            stats: Stats::default(),
            stats_at: std::env::var_os("NETD_STATS").map(|_| Instant::now()),
            cid: cfg.cid,
            aliases: cfg.aliases.clone(),
            listen_port: cfg.listen_port,
            guest_port: cfg.guest_port,
            forwards,
            mem: None,
            event_idx: false,
            epoll,
            conns: HashMap::new(),
            ports: HashMap::new(),
            next_tok: 1,
            next_port: FIRST_HOST_PORT,
            ctl: VecDeque::new(),
            rx_ready: HashSet::new(),
            tx_ready: HashSet::new(),
            shm_ready: HashSet::new(),
            shm_toks: Vec::new(),
            shm: None,
            busy_poll: cfg.busy_poll,
            yield_fd,
            segs: Vec::with_capacity(512),
            iov: Vec::with_capacity(512),
        })
    }

    fn run(&mut self, vrings: &[VringRwLock]) -> io::Result<()> {
        let Some(atomic) = self.mem.clone() else { return Ok(()) };
        let guard = atomic.memory();
        let mem: &Mem = &guard;
        self.stats.wakeups += 1;
        let start = Instant::now();
        let mut last_work = start;
        let mut toks = std::mem::take(&mut self.shm_toks);
        loop {
            let before = self.stats.work();
            self.poll_epoll();
            self.process_tx(&vrings[TXQ], mem)?;
            self.flush_tx_ready();
            // While busy-polling, the rings are serviced without arming their
            // wait flags, so the agent has no reason to ring the doorbell.
            let busy = !self.busy_poll.is_zero() && self.conns.values().any(|c| c.shm.is_some() && !c.bulk);
            toks.clear();
            if busy {
                self.shm_conns(&mut toks);
                self.shm_ready.clear();
            } else {
                toks.extend(self.shm_ready.drain());
            }
            self.pump_shm(&toks, !busy);
            self.process_rx(&vrings[RXQ], mem)?;
            if !busy {
                if self.shm_ready.is_empty() {
                    break;
                }
                continue;
            }
            self.stats.busy_polls += 1;
            if self.stats.work() != before {
                last_work = Instant::now();
            }
            if start.elapsed() >= MAX_POLL {
                // Still busy: come back through the event loop.
                unsafe { libc::eventfd_write(self.yield_fd.as_raw_fd(), 1) };
                break;
            }
            if last_work.elapsed() >= self.busy_poll {
                // Idle: arm the rings and sleep, unless arming found work.
                let before = self.stats.work();
                toks.clear();
                self.shm_conns(&mut toks);
                self.pump_shm(&toks, true);
                self.process_rx(&vrings[RXQ], mem)?;
                if self.stats.work() == before {
                    break;
                }
                last_work = Instant::now();
            }
            std::hint::spin_loop();
        }
        self.shm_toks = toks;
        self.print_stats();
        Ok(())
    }

    fn shm_conns(&self, toks: &mut Vec<u64>) {
        toks.extend(self.conns.iter().filter(|(_, c)| c.shm.is_some()).map(|(&t, _)| t));
    }

    fn print_stats(&mut self) {
        let Some(at) = self.stats_at else { return };
        if at.elapsed().as_secs() < 1 {
            return;
        }
        if self.stats.wakeups > 1 {
            eprintln!("netd: stats {:?} conns={}", self.stats, self.conns.len());
        }
        self.stats = Stats::default();
        self.stats_at = Some(Instant::now());
    }

    // ---- host sockets ----

    fn poll_epoll(&mut self) {
        let mut evs = [libc::epoll_event { events: 0, u64: 0 }; 64];
        loop {
            let n = unsafe { libc::epoll_wait(self.epoll.as_raw_fd(), evs.as_mut_ptr(), evs.len() as i32, 0) };
            if n <= 0 {
                return;
            }
            self.stats.epoll_events += n as u64;
            for e in &evs[..n as usize] {
                let (ev, tok) = (e.events, e.u64);
                if tok == YIELD_TOK {
                    let mut v = 0;
                    unsafe { libc::eventfd_read(self.yield_fd.as_raw_fd(), &mut v) };
                    continue;
                }
                if tok & LISTENER_BIT != 0 {
                    self.accept_forward((tok & !LISTENER_BIT) as usize);
                    continue;
                }
                let Some(c) = self.conns.get_mut(&tok) else { continue };
                let hup = (libc::EPOLLERR | libc::EPOLLHUP) as u32;
                if c.state == State::Connecting && ev & (libc::EPOLLOUT as u32 | hup) != 0 {
                    self.finish_connect(tok);
                    continue;
                }
                if ev & (libc::EPOLLIN as u32 | libc::EPOLLRDHUP as u32 | hup) != 0 {
                    c.readable = true;
                    if c.shm.is_none() {
                        self.rx_ready.insert(tok);
                    }
                }
                if ev & (libc::EPOLLOUT as u32 | hup) != 0 {
                    c.writable = true;
                    if c.shm.is_none() {
                        self.tx_ready.insert(tok);
                    }
                }
                if c.shm.is_some() {
                    self.shm_ready.insert(tok);
                }
            }
            if (n as usize) < evs.len() {
                return;
            }
        }
    }

    fn add_conn(&mut self, c: Conn) -> u64 {
        let tok = self.next_tok;
        self.next_tok += 1;
        self.ports.insert((c.local_port, c.peer_port), tok);
        self.conns.insert(tok, c);
        tok
    }

    fn accept_forward(&mut self, idx: usize) {
        let forwards = self.forwards.clone();
        let (l, gport) = &forwards[idx];
        loop {
            let s = match l.accept() {
                Ok((s, _)) => s,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
                Err(e) => {
                    eprintln!("netd: forward accept: {e}");
                    return;
                }
            };
            if s.set_nonblocking(true).is_err() {
                continue;
            }
            let fd: OwnedFd = s.into();
            set_nodelay(fd.as_raw_fd());
            let mut local = self.next_port;
            while self.ports.contains_key(&(local, self.guest_port)) {
                local = local.wrapping_add(1).max(FIRST_HOST_PORT);
            }
            self.next_port = local.wrapping_add(1).max(FIRST_HOST_PORT);
            let mut c = Conn::new(local, self.guest_port, State::AwaitResponse);
            c.prefix = Request::tcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), *gport), NO_SLOT).encode();
            let raw = fd.as_raw_fd();
            c.sock = Some(fd);
            let tok = self.add_conn(c);
            if let Err(e) = epoll_add(self.epoll.as_raw_fd(), raw, SOCK_EVENTS, tok) {
                eprintln!("netd: epoll: {e}");
                self.remove(tok);
                continue;
            }
            self.ctl.push_back(Ctl { local_port: local, peer_port: self.guest_port, op: OP_REQUEST, flags: 0 });
        }
    }

    fn start_connect(&mut self, tok: u64, req: Request) {
        let res = if req.proto == PROTO_TCP {
            connect_nb(crate::map_dst(&self.aliases, req.dst)).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))
        } else {
            Err(libc::EPROTONOSUPPORT)
        };
        match res {
            Ok((fd, in_progress)) => {
                let raw = fd.as_raw_fd();
                let c = self.conns.get_mut(&tok).unwrap();
                c.sock = Some(fd);
                c.state = State::Connecting;
                if let Err(e) = epoll_add(self.epoll.as_raw_fd(), raw, SOCK_EVENTS, tok) {
                    self.fail(tok, e.raw_os_error().unwrap_or(libc::EIO));
                } else if !in_progress {
                    self.connected(tok);
                }
            }
            Err(e) => self.fail(tok, e),
        }
    }

    fn finish_connect(&mut self, tok: u64) {
        let fd = self.conns[&tok].sock.as_ref().unwrap().as_raw_fd();
        match so_error(fd) {
            0 => self.connected(tok),
            e => self.fail(tok, e),
        }
    }

    fn connected(&mut self, tok: u64) {
        if let Some(slot) = self.conns[&tok].bound {
            // Slot streams only hear back on failure.
            if !self.attach_slot(tok, slot) {
                self.end(tok, Some(libc::EIO));
                return;
            }
        }
        let c = self.conns.get_mut(&tok).unwrap();
        c.state = State::Relay;
        if c.bound.is_none() {
            c.prefix.extend_from_slice(&proto::encode_status(0, NO_SLOT));
        }
        c.writable = true;
        c.readable = true;
        self.rx_ready.insert(tok);
        self.tx_ready.insert(tok);
        self.shm_ready.insert(tok);
    }

    /// Registers the agent's rings, replacing (and resetting the connections
    /// of) any earlier registration, e.g. from before a guest reboot.
    fn register_shm(&mut self, r: &ShmRegion) -> Result<(), i32> {
        let guard = self.mem.as_ref().ok_or(libc::ENODEV)?.memory();
        let map = |gpa: u64, len: usize| -> Result<*mut u8, i32> {
            let s = guard.get_slice(GuestAddress(gpa), len).map_err(|_| libc::EFAULT)?;
            let p = s.ptr_guard_mut().as_ptr();
            if !(p as usize).is_multiple_of(64) {
                return Err(libc::EINVAL);
            }
            Ok(p)
        };
        let ctl = map(r.ctl_gpa, r.slots() * SLOT_CTL)?;
        let rings = r.ring_gpas.iter().map(|&g| map(g, RING_SIZE)).collect::<Result<Vec<_>, _>>()?;
        let old: Vec<u64> = self.conns.iter().filter(|(_, c)| c.shm.is_some() || c.bound.is_some()).map(|(&t, _)| t).collect();
        for tok in old {
            self.reset(tok);
        }
        let n = r.slots();
        self.shm = Some(ShmTable { _mem: guard.into_inner(), ctl, rings, in_use: vec![false; n], bound: vec![false; n] });
        eprintln!("netd: shared rings registered ({} slots)", r.slots());
        Ok(())
    }

    /// Makes the stream `slot`'s stream; returns the status for the agent.
    fn bind_slot(&mut self, tok: u64, slot: u16) -> i32 {
        let Some(t) = self.shm.as_mut() else { return libc::ENODEV };
        let i = slot as usize;
        if i >= t.bound.len() || t.bound[i] {
            return libc::EINVAL;
        }
        t.bound[i] = true;
        let c = self.conns.get_mut(&tok).unwrap();
        c.bound = Some(slot);
        c.state = State::SlotIdle;
        0
    }

    fn slot_ctl(&self, slot: u16) -> Option<&SlotCtl> {
        let t = self.shm.as_ref()?;
        // SAFETY: slot < slots (checked at bind), and the control block stays
        // mapped while the table holds the memory.
        (usize::from(slot) < t.bound.len()).then(|| unsafe { &*(t.ctl.add(usize::from(slot) * SLOT_CTL) as *const SlotCtl) })
    }

    /// Handles a frame from the agent on a slot stream.
    fn slot_frame(&mut self, tok: u64, f: Frame) {
        let Some(c) = self.conns.get_mut(&tok) else { return };
        match (f, c.state) {
            (Frame::Bell, _) => {
                if c.shm.is_some() {
                    self.stats.bells_in += 1;
                    self.shm_ready.insert(tok);
                }
            }
            (Frame::Open { id, dst }, State::SlotIdle) => {
                c.conn_id = id;
                self.start_connect(tok, Request::tcp(dst, NO_SLOT));
            }
            // A connection netd already ended (Fail) or that has not started.
            (Frame::Close | Frame::Reset, State::SlotIdle) => {}
            (Frame::Close, _) => {
                c.guest_done = true;
                self.shm_ready.insert(tok);
                self.check_done(tok);
            }
            (Frame::Reset, _) => {
                c.guest_done = true;
                self.end(tok, None);
            }
            _ => self.reset(tok),
        }
    }

    /// Ends the connection on a slot stream: the host socket closes, the
    /// slot is free for the agent's next connection and, unless the agent
    /// ended it, `err` tells it why. Other streams are reset.
    fn end(&mut self, tok: u64, err: Option<i32>) {
        let Some(c) = self.conns.get_mut(&tok) else { return };
        let Some(slot) = c.bound else {
            self.reset(tok);
            return;
        };
        if let Some(e) = err.filter(|_| !c.guest_done) {
            Frame::Fail { id: c.conn_id, errno: e }.encode(&mut c.prefix);
            self.rx_ready.insert(tok);
        }
        let shm = c.shm.take();
        c.clear_conn();
        if let (Some(s), Some(t)) = (shm, self.shm.as_mut()) {
            t.in_use[s.slot as usize] = false;
        }
        if let Some(ctl) = self.slot_ctl(slot) {
            ctl.release();
        }
        self.tx_ready.remove(&tok);
        self.shm_ready.remove(&tok);
    }

    /// Binds `slot` of the registered rings to the connection.
    fn attach_slot(&mut self, tok: u64, slot: u16) -> bool {
        let Some(t) = self.shm.as_mut() else { return false };
        let i = slot as usize;
        if slot == NO_SLOT || i >= t.in_use.len() || t.in_use[i] {
            return false;
        }
        t.in_use[i] = true;
        // SAFETY: the control block and both rings were mapped and checked at
        // registration and stay mapped while the table holds the memory.
        let sc = unsafe {
            let ctl = t.ctl.add(i * SLOT_CTL) as *const SlotCtl;
            let g2h = Ring::new(&(*ctl).g2h, t.rings[2 * i]);
            let h2g = Ring::new(&(*ctl).h2g, t.rings[2 * i + 1]);
            ShmConn { slot, ctl, tx: Consumer::new(g2h), rx: Producer::new(h2g) }
        };
        self.conns.get_mut(&tok).unwrap().shm = Some(sc);
        true
    }

    fn pump_shm(&mut self, toks: &[u64], arm: bool) {
        for &tok in toks {
            let Some(c) = self.conns.get_mut(&tok) else { continue };
            if c.state != State::Relay {
                continue;
            }
            match c.pump_shm(&mut self.stats, arm) {
                Ok(bell) => {
                    // One pending byte is enough to wake the agent.
                    if bell && !c.guest_shut_rcv && c.prefix.is_empty() {
                        Frame::Bell.encode(&mut c.prefix);
                        self.stats.bells_out += 1;
                        self.rx_ready.insert(tok);
                    }
                    if bell {
                        self.shm_ready.insert(tok);
                    }
                    self.check_done(tok);
                }
                Err(_) => self.end(tok, Some(libc::ECONNRESET)),
            }
        }
    }

    /// Reports a setup error to the guest agent; the agent then closes.
    fn fail(&mut self, tok: u64, err: i32) {
        if self.conns[&tok].bound.is_some() {
            self.end(tok, Some(err));
            return;
        }
        let c = self.conns.get_mut(&tok).unwrap();
        c.state = State::Failed;
        c.sock = None;
        c.txq.clear();
        c.prefix.extend_from_slice(&proto::encode_status(err, NO_SLOT));
        self.rx_ready.insert(tok);
    }

    fn remove(&mut self, tok: u64) {
        if let Some(c) = self.conns.remove(&tok) {
            self.ports.remove(&(c.local_port, c.peer_port));
            if let (Some(s), Some(t)) = (&c.shm, self.shm.as_mut()) {
                t.in_use[s.slot as usize] = false;
                // SAFETY: mapped while the table lives; this is netd's last access.
                unsafe { (*s.ctl).release() };
            }
            if let Some(slot) = c.bound {
                if c.state != State::SlotIdle
                    && let Some(ctl) = self.slot_ctl(slot)
                {
                    ctl.release();
                }
                if let Some(t) = self.shm.as_mut() {
                    t.bound[slot as usize] = false;
                }
            }
        }
        self.rx_ready.remove(&tok);
        self.tx_ready.remove(&tok);
        self.shm_ready.remove(&tok);
    }

    fn reset(&mut self, tok: u64) {
        if let Some(c) = self.conns.get(&tok) {
            self.ctl.push_back(Ctl { local_port: c.local_port, peer_port: c.peer_port, op: OP_RST, flags: 0 });
        }
        self.remove(tok);
    }

    fn maybe_credit(&mut self, tok: u64) {
        let Some(c) = self.conns.get_mut(&tok) else { return };
        // The guest believes rx_cnt - last_fwd_sent bytes are in flight.
        // Refresh its view once that passes a quarter of the window.
        if !c.credit_queued
            && c.fwd_cnt != c.last_fwd_sent
            && c.rx_cnt.wrapping_sub(c.last_fwd_sent) >= BUF_ALLOC / 4
        {
            c.credit_queued = true;
            self.ctl.push_back(Ctl { local_port: c.local_port, peer_port: c.peer_port, op: OP_CREDIT_UPDATE, flags: 0 });
        }
    }

    /// Closes connections whose both directions are finished.
    fn check_done(&mut self, tok: u64) {
        let Some(c) = self.conns.get_mut(&tok) else { return };
        if let Some(s) = &c.shm {
            // EOF travels in the rings; the agent says when it is done
            // (Close, or closing a forward's stream), possibly leaving payload
            // in the ring for netd to flush.
            let done = if c.bound.is_some() { c.guest_done } else { c.guest_shut_send && c.guest_shut_rcv };
            if done && (c.wr_shut || !matches!(s.tx.avail(), Ok(n) if n > 0)) {
                self.end(tok, None);
            }
            return;
        }
        if c.bound.is_some() {
            return; // still connecting; the rings are attached once connected
        }
        if !c.txq.is_empty() {
            return;
        }
        if c.guest_shut_send && !c.wr_shut {
            if let Some(s) = &c.sock {
                unsafe { libc::shutdown(s.as_raw_fd(), libc::SHUT_WR) };
            }
            c.wr_shut = true;
        }
        if c.guest_shut_send && c.guest_shut_rcv {
            self.reset(tok);
        }
    }

    fn flush_tx_ready(&mut self) {
        let toks: Vec<u64> = self.tx_ready.drain().collect();
        for tok in toks {
            self.flush(tok);
        }
    }

    /// Writes buffered guest payload to the host socket.
    fn flush(&mut self, tok: u64) {
        let Some(c) = self.conns.get_mut(&tok) else { return };
        if c.state == State::Relay && c.writable && !c.txq.is_empty() {
            let fd = c.sock.as_ref().unwrap().as_raw_fd();
            while !c.txq.is_empty() {
                let (a, b) = c.txq.as_slices();
                let iov = [
                    libc::iovec { iov_base: a.as_ptr() as *mut _, iov_len: a.len() },
                    libc::iovec { iov_base: b.as_ptr() as *mut _, iov_len: b.len() },
                ];
                let want = a.len() + b.len();
                let n = unsafe { libc::writev(fd, iov.as_ptr(), if b.is_empty() { 1 } else { 2 }) };
                if n < 0 {
                    match errno() {
                        libc::EINTR => continue,
                        libc::EAGAIN => {
                            c.writable = false;
                            break;
                        }
                        _ => {
                            self.reset(tok);
                            return;
                        }
                    }
                }
                c.txq.drain(..n as usize);
                c.fwd_cnt = c.fwd_cnt.wrapping_add(n as u32);
                if (n as usize) < want {
                    c.writable = false;
                    break;
                }
            }
        }
        self.maybe_credit(tok);
        self.check_done(tok);
    }

    // ---- guest -> host (TX queue) ----

    fn process_tx(&mut self, vring: &VringRwLock, mem: &Mem) -> io::Result<()> {
        let mut st = vring.get_mut();
        if !st.get_queue().ready() {
            return Ok(());
        }
        let mut used = false;
        let mut segs = std::mem::take(&mut self.segs);
        loop {
            let _ = st.disable_notification();
            loop {
                segs.clear();
                let Some(head) = pop_chain(&mut st, mem, false, &mut segs) else { break };
                self.stats.tx_pkts += 1;
                self.on_tx_packet(&segs);
                let _ = st.add_used(head, 0);
                used = true;
            }
            if !st.enable_notification().map_err(io::Error::other)? {
                break;
            }
        }
        segs.clear();
        self.segs = segs;
        if used && st.needs_notification().map_err(io::Error::other)? {
            self.stats.tx_irqs += 1;
            st.signal_used_queue()?;
        }
        Ok(())
    }

    fn on_tx_packet(&mut self, segs: &[Seg]) {
        let total = segs_len(segs);
        if total < HDR {
            return;
        }
        let mut hb = [0u8; HDR];
        segs_read(segs, 0, &mut hb);
        let h = Hdr::parse(&hb);
        if h.src_cid != self.cid || h.dst_cid != HOST_CID {
            return;
        }
        let len = (h.len as usize).min(total - HDR);
        let key = (h.dst_port, h.src_port);
        let Some(&tok) = self.ports.get(&key) else {
            if h.typ == TYPE_STREAM && h.op == OP_REQUEST && h.dst_port == self.listen_port {
                let mut c = Conn::new(h.dst_port, h.src_port, State::ReadReq);
                c.peer_buf_alloc = h.buf_alloc;
                c.peer_fwd_cnt = h.fwd_cnt;
                self.add_conn(c);
                self.ctl.push_back(Ctl { local_port: h.dst_port, peer_port: h.src_port, op: OP_RESPONSE, flags: 0 });
            } else if h.op != OP_RST {
                self.ctl.push_back(Ctl { local_port: h.dst_port, peer_port: h.src_port, op: OP_RST, flags: 0 });
            }
            return;
        };
        if h.typ != TYPE_STREAM {
            self.reset(tok);
            return;
        }
        let c = self.conns.get_mut(&tok).unwrap();
        c.peer_buf_alloc = h.buf_alloc;
        c.peer_fwd_cnt = h.fwd_cnt;
        self.rx_ready.insert(tok);
        match h.op {
            OP_RW => self.guest_data(tok, segs, HDR, len),
            OP_RESPONSE => {
                if c.state == State::AwaitResponse {
                    c.state = State::AwaitStatus;
                } else {
                    self.reset(tok);
                }
            }
            OP_CREDIT_UPDATE => {}
            OP_CREDIT_REQUEST => {
                self.ctl.push_back(Ctl { local_port: key.0, peer_port: key.1, op: OP_CREDIT_UPDATE, flags: 0 })
            }
            // The agent only closes a slot stream when it gives up the
            // registration.
            OP_SHUTDOWN if c.bound.is_some() => self.reset(tok),
            OP_SHUTDOWN => {
                c.guest_shut_send |= h.flags & SHUT_SEND != 0;
                c.guest_shut_rcv |= h.flags & SHUT_RCV != 0;
                if c.shm.is_some() {
                    self.shm_ready.insert(tok);
                }
                self.check_done(tok);
            }
            OP_RST => self.remove(tok),
            _ => self.reset(tok),
        }
    }

    fn guest_data(&mut self, tok: u64, segs: &[Seg], mut off: usize, mut len: usize) {
        self.stats.tx_bytes += len as u64;
        let c = self.conns.get_mut(&tok).unwrap();
        c.rx_cnt = c.rx_cnt.wrapping_add(len as u32);
        while len > 0 && matches!(c.state, State::ReadReq | State::AwaitStatus) {
            let need = if c.state == State::ReadReq { Msg::need(&c.hs) } else { STATUS_LEN };
            let take = (need - c.hs.len()).min(len);
            let at = c.hs.len();
            c.hs.resize(at + take, 0);
            segs_read(segs, off, &mut c.hs[at..]);
            off += take;
            len -= take;
            c.fwd_cnt = c.fwd_cnt.wrapping_add(take as u32);
            if c.hs.len() < need {
                continue;
            }
            if c.state == State::ReadReq {
                if Msg::need(&c.hs) > need {
                    continue; // the prefix revealed more header to read
                }
                let parsed = Msg::parse(&c.hs);
                c.hs.clear();
                match parsed {
                    Ok(Msg::Connect(req)) => self.start_connect(tok, req),
                    Ok(Msg::Slot(slot)) => {
                        let err = self.bind_slot(tok, slot);
                        let c = self.conns.get_mut(&tok).unwrap();
                        c.prefix.extend_from_slice(&proto::encode_status(err, slot));
                        if err != 0 {
                            c.state = State::Failed;
                        }
                        self.rx_ready.insert(tok);
                    }
                    Ok(Msg::Shm(r)) => {
                        let err = self.register_shm(&r).err().unwrap_or(0);
                        let c = self.conns.get_mut(&tok).unwrap();
                        c.state = State::Registration;
                        c.prefix.extend_from_slice(&proto::encode_status(err, NO_SLOT));
                        self.rx_ready.insert(tok);
                    }
                    Err(_) => {
                        self.reset(tok);
                        return;
                    }
                }
            } else {
                let (st, slot) = proto::parse_status(c.hs[..STATUS_LEN].try_into().unwrap());
                c.hs.clear();
                if st != 0 || (slot != NO_SLOT && !self.attach_slot(tok, slot)) {
                    self.reset(tok);
                    return;
                }
                let c = self.conns.get_mut(&tok).unwrap();
                c.state = State::Relay;
                c.readable = true;
                c.writable = true;
                self.shm_ready.insert(tok);
            }
            break;
        }
        let Some(c) = self.conns.get_mut(&tok) else { return };
        if c.bound.is_some() && c.state != State::ReadReq {
            c.fwd_cnt = c.fwd_cnt.wrapping_add(len as u32);
            let mut b = vec![0u8; len];
            segs_read(segs, off, &mut b);
            let mut frames = std::mem::take(&mut c.frames);
            let mut got = Vec::new();
            let ok = frames
                .feed(&b, |f| {
                    got.push(f);
                    Ok(())
                })
                .is_ok();
            for f in got {
                self.slot_frame(tok, f);
            }
            match self.conns.get_mut(&tok) {
                Some(c) if ok => c.frames = frames,
                Some(_) => self.reset(tok),
                None => return,
            }
            self.maybe_credit(tok);
            return;
        }
        if c.shm.is_some() || c.state == State::Registration {
            // Doorbells (or nothing at all): the payload is in the rings.
            c.fwd_cnt = c.fwd_cnt.wrapping_add(len as u32);
            if len > 0 && c.shm.is_some() {
                self.stats.bells_in += 1;
                self.shm_ready.insert(tok);
            }
            self.maybe_credit(tok);
            return;
        }
        if len > 0 && c.state == State::Relay && c.txq.is_empty() && c.writable {
            let fd = c.sock.as_ref().unwrap().as_raw_fd();
            self.iov.clear();
            segs_iov(segs, off, len, &mut self.iov);
            let n = loop {
                let n = unsafe { libc::writev(fd, self.iov.as_ptr(), self.iov.len().min(1024) as i32) };
                if n >= 0 || errno() != libc::EINTR {
                    break n;
                }
            };
            if n < 0 {
                if errno() != libc::EAGAIN {
                    self.reset(tok);
                    return;
                }
                c.writable = false;
            } else {
                let n = n as usize;
                c.fwd_cnt = c.fwd_cnt.wrapping_add(n as u32);
                if n < len {
                    c.writable = false;
                }
                off += n;
                len -= n;
            }
        }
        if len > 0 && c.state != State::Failed {
            let at = c.txq.len();
            c.txq.resize(at + len, 0);
            let buf = c.txq.make_contiguous();
            segs_read(segs, off, &mut buf[at..]);
            self.stats.tx_buffered += len as u64;
            self.tx_ready.insert(tok);
        } else if len > 0 {
            c.fwd_cnt = c.fwd_cnt.wrapping_add(len as u32);
        }
        self.maybe_credit(tok);
    }

    // ---- host -> guest (RX queue) ----

    fn process_rx(&mut self, vring: &VringRwLock, mem: &Mem) -> io::Result<()> {
        let mut st = vring.get_mut();
        if !st.get_queue().ready() {
            return Ok(());
        }
        let mut used = false;
        loop {
            let _ = st.disable_notification();
            let starved = self.fill_rx(&mut st, mem, &mut used);
            // Ask for a kick only when buffers ran out with work pending.
            if !starved {
                break;
            }
            self.stats.rx_starved += 1;
            if !st.enable_notification().map_err(io::Error::other)? {
                break;
            }
        }
        if used && st.needs_notification().map_err(io::Error::other)? {
            self.stats.rx_irqs += 1;
            st.signal_used_queue()?;
        }
        Ok(())
    }

    /// Returns true when it stopped because the RX queue has no buffers.
    fn fill_rx(&mut self, st: &mut VState, mem: &Mem, used: &mut bool) -> bool {
        loop {
            while let Some(ctl) = self.ctl.front() {
                self.segs.clear();
                let mut segs = std::mem::take(&mut self.segs);
                let Some(head) = pop_chain(st, mem, true, &mut segs) else {
                    self.segs = segs;
                    return true;
                };
                let mut h = Hdr {
                    src_cid: HOST_CID,
                    dst_cid: self.cid,
                    src_port: ctl.local_port,
                    dst_port: ctl.peer_port,
                    typ: TYPE_STREAM,
                    op: ctl.op,
                    flags: ctl.flags,
                    ..Default::default()
                };
                if let Some(c) = self.ports.get(&(ctl.local_port, ctl.peer_port)).and_then(|t| self.conns.get_mut(t)) {
                    h.buf_alloc = BUF_ALLOC;
                    h.fwd_cnt = c.fwd_cnt;
                    c.last_fwd_sent = c.fwd_cnt;
                    if ctl.op == OP_CREDIT_UPDATE {
                        c.credit_queued = false;
                    }
                }
                if segs_len(&segs) >= HDR {
                    segs_write(&segs, 0, &h.encode());
                }
                let _ = st.add_used(head, HDR as u32);
                *used = true;
                self.segs = segs;
                self.stats.ctl_pkts += 1;
                if ctl.op == OP_CREDIT_UPDATE {
                    self.stats.credit_updates += 1;
                }
                self.ctl.pop_front();
            }
            let toks: Vec<u64> = self.rx_ready.drain().collect();
            for (i, &tok) in toks.iter().enumerate() {
                loop {
                    match self.rx_conn(tok, st, mem, used) {
                        Rx::Sent => continue,
                        Rx::Idle => break,
                        Rx::Starved => {
                            self.rx_ready.extend(&toks[i..]);
                            return true;
                        }
                    }
                }
            }
            if self.ctl.is_empty() {
                return false;
            }
        }
    }

    fn rx_hdr(&self, c: &Conn, op: u16, len: u32, flags: u32) -> Hdr {
        Hdr {
            src_cid: HOST_CID,
            dst_cid: self.cid,
            src_port: c.local_port,
            dst_port: c.peer_port,
            len,
            typ: TYPE_STREAM,
            op,
            flags,
            buf_alloc: BUF_ALLOC,
            fwd_cnt: c.fwd_cnt,
        }
    }

    fn rx_conn(&mut self, tok: u64, st: &mut VState, mem: &Mem, used: &mut bool) -> Rx {
        let Some(c) = self.conns.get(&tok) else { return Rx::Idle };
        let credit = c.peer_credit();
        if !c.prefix.is_empty()
            && (c.bound.is_some() || matches!(c.state, State::AwaitStatus | State::Relay | State::Failed | State::Registration))
        {
            if credit == 0 {
                return Rx::Idle;
            }
            let mut segs = std::mem::take(&mut self.segs);
            segs.clear();
            let Some(head) = pop_chain(st, mem, true, &mut segs) else {
                self.segs = segs;
                return Rx::Starved;
            };
            let cap = segs_len(&segs).saturating_sub(HDR);
            let n = c.prefix.len().min(credit).min(cap);
            let h = self.rx_hdr(c, OP_RW, n as u32, 0);
            segs_write(&segs, 0, &h.encode());
            segs_write(&segs, HDR, &c.prefix[..n]);
            let _ = st.add_used(head, (HDR + n) as u32);
            *used = true;
            self.segs = segs;
            let c = self.conns.get_mut(&tok).unwrap();
            c.prefix.drain(..n);
            c.tx_cnt = c.tx_cnt.wrapping_add(n as u32);
            c.last_fwd_sent = c.fwd_cnt;
            return Rx::Sent;
        }
        if c.state != State::Relay || c.shm.is_some() || !c.readable || c.sock_eof || c.guest_shut_rcv || credit == 0 {
            return Rx::Idle;
        }
        let fd = c.sock.as_ref().unwrap().as_raw_fd();
        let want = credit.min(RX_BATCH);

        // Collect chains until the batch is full, then fill them with one readv.
        let start = st.get_queue().next_avail();
        let mut segs = std::mem::take(&mut self.segs);
        let mut iov = std::mem::take(&mut self.iov);
        segs.clear();
        iov.clear();
        let mut chains: Vec<(u16, usize, usize, usize)> = Vec::new(); // head, seg start, seg end, data cap
        let mut total = 0;
        while total < want && iov.len() < 1000 {
            let s0 = segs.len();
            let Some(head) = pop_chain(st, mem, true, &mut segs) else { break };
            let cap = segs_len(&segs[s0..]).saturating_sub(HDR).min(want - total);
            segs_iov(&segs[s0..], HDR, cap, &mut iov);
            chains.push((head, s0, segs.len(), cap));
            total += cap;
        }
        if chains.is_empty() {
            self.segs = segs;
            self.iov = iov;
            return Rx::Starved;
        }
        let n = loop {
            let n = unsafe { libc::readv(fd, iov.as_ptr(), iov.len() as i32) };
            if n >= 0 || errno() != libc::EINTR {
                break n;
            }
        };
        let err = if n < 0 { errno() } else { 0 };
        let got = n.max(0) as usize;
        self.stats.rx_readv += 1;
        self.stats.rx_bytes += got as u64;
        let mut rem = got;
        let mut nused = 0u16;
        for &(head, s0, s1, cap) in &chains {
            if rem == 0 {
                break;
            }
            let k = cap.min(rem);
            let c = &self.conns[&tok];
            segs_write(&segs[s0..s1], 0, &self.rx_hdr(c, OP_RW, k as u32, 0).encode());
            let _ = st.add_used(head, (HDR + k) as u32);
            rem -= k;
            nused += 1;
        }
        self.stats.rx_chains += u64::from(nused);
        // Hand unused chains back to the queue.
        st.get_queue_mut().set_next_avail(start.wrapping_add(nused));
        self.segs = segs;
        self.iov = iov;
        let c = self.conns.get_mut(&tok).unwrap();
        if got > 0 {
            *used = true;
            c.tx_cnt = c.tx_cnt.wrapping_add(got as u32);
            c.last_fwd_sent = c.fwd_cnt;
            if got < total {
                c.readable = false; // edge-triggered: a short read drained the socket
            }
            return Rx::Sent;
        }
        if n == 0 {
            c.sock_eof = true;
            self.ctl.push_back(Ctl { local_port: c.local_port, peer_port: c.peer_port, op: OP_SHUTDOWN, flags: SHUT_SEND });
            return Rx::Idle;
        }
        if err == libc::EAGAIN {
            c.readable = false;
        } else {
            self.reset(tok);
        }
        Rx::Idle
    }
}

struct Backend {
    dev: Mutex<Dev>,
    cid: u64,
    exit: (EventConsumer, EventNotifier),
}

impl VhostUserBackend for Backend {
    type Bitmap = ();
    type Vring = VringRwLock;

    fn num_queues(&self) -> usize {
        NUM_QUEUES
    }

    fn max_queue_size(&self) -> usize {
        1024
    }

    fn features(&self) -> u64 {
        (1 << VIRTIO_F_VERSION_1) | (1 << VIRTIO_RING_F_EVENT_IDX) | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::MQ | VhostUserProtocolFeatures::CONFIG
    }

    fn set_event_idx(&self, enabled: bool) {
        self.dev.lock().unwrap().event_idx = enabled;
    }

    fn update_memory(&self, mem: GuestMemoryAtomic<GuestMemoryMmap>) -> io::Result<()> {
        self.dev.lock().unwrap().mem = Some(mem);
        Ok(())
    }

    fn get_config(&self, offset: u32, size: u32) -> Vec<u8> {
        let cfg = self.cid.to_le_bytes();
        let (o, s) = (offset as usize, size as usize);
        if o + s > cfg.len() {
            return Vec::new();
        }
        cfg[o..o + s].to_vec()
    }

    fn exit_event(&self, _thread_index: usize) -> Option<(EventConsumer, EventNotifier)> {
        Some((self.exit.0.try_clone().ok()?, self.exit.1.try_clone().ok()?))
    }

    fn handle_event(&self, device_event: u16, _evset: EventSet, vrings: &[VringRwLock], _thread: usize) -> io::Result<()> {
        if device_event == EVQ {
            return Ok(());
        }
        self.dev.lock().unwrap().run(vrings)
    }
}

/// Serves the vhost-user socket forever; a new device is created for every
/// frontend (QEMU) connection.
pub fn serve(socket: &str, cfg: Config) -> ! {
    let Config { cid, aliases, listen_port, guest_port, forwards, busy_poll } = cfg;
    let forwards = Arc::new(forwards);
    let cfg = Config { cid, aliases, listen_port, guest_port, forwards: Vec::new(), busy_poll };
    loop {
        if let Err(e) = serve_once(socket, &cfg, forwards.clone()) {
            eprintln!("netd: vhost-user: {e}");
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }
}

fn serve_once(socket: &str, cfg: &Config, forwards: Arc<Vec<(TcpListener, u16)>>) -> io::Result<()> {
    let exit = new_event_consumer_and_notifier(EventFlag::NONBLOCK)?;
    let dev = Dev::new(cfg, forwards)?;
    let epfd = dev.epoll.as_raw_fd();
    let backend = Arc::new(Backend { dev: Mutex::new(dev), cid: cfg.cid, exit });
    let mut daemon = VhostUserDaemon::new("netd".into(), backend, GuestMemoryAtomic::new(GuestMemoryMmap::new()))
        .map_err(|e| io::Error::other(format!("{e:?}")))?;
    for h in daemon.get_epoll_handlers() {
        h.register_listener(epfd, EventSet::IN, u64::from(EPOLL_EVENT))?;
    }
    let _ = std::fs::remove_file(socket);
    eprintln!("netd: vhost-user-vsock listening on {socket} (guest cid {})", cfg.cid);
    daemon.serve(socket).map_err(|e| io::Error::other(format!("{e:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let h = Hdr {
            src_cid: 3,
            dst_cid: 2,
            src_port: 1234,
            dst_port: 1024,
            len: 77,
            typ: TYPE_STREAM,
            op: OP_RW,
            flags: 3,
            buf_alloc: 1 << 20,
            fwd_cnt: 99,
        };
        assert_eq!(Hdr::parse(&h.encode()), h);
    }

    #[test]
    fn segs_cross_boundaries() {
        let mut a = [0u8; 3];
        let mut b = [0u8; 5];
        let segs = [Seg { ptr: a.as_mut_ptr(), len: 3 }, Seg { ptr: b.as_mut_ptr(), len: 5 }];
        segs_write(&segs, 1, b"hello");
        let mut out = [0u8; 5];
        segs_read(&segs, 1, &mut out);
        assert_eq!(&out, b"hello");
        let mut iov = Vec::new();
        segs_iov(&segs, 2, 4, &mut iov);
        assert_eq!(iov.iter().map(|v| v.iov_len).collect::<Vec<_>>(), vec![1, 3]);
        assert_eq!(&a, b"\0he");
        assert_eq!(&b[..3], b"llo");
    }

}
