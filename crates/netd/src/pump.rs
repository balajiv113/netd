//! Data plane for connections on the agent's shared rings.
//!
//! Worker threads move payload between host sockets and the rings in guest
//! memory, so streams spread over cores instead of sharing the vhost-user
//! thread. That thread (vu.rs) keeps the vsock side of each connection: the
//! handshake, the doorbell bytes in both directions and teardown. It talks to
//! the workers through command queues; workers report back through `Events`.
//!
//! A worker busy-polls a stream for `busy_poll` after it last moved data,
//! like vhost-net's busyloop: meanwhile the ring wait flags stay unarmed, so
//! the agent has no reason to ring the doorbell. Idle streams are armed and
//! left to epoll (socket) and kicks (doorbells from the agent).

use std::collections::{HashMap, HashSet};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use netd_common::shm::{CHUNK, Consumer, Producer, Ring, SLOT_CTL, SlotCtl};

const INBOX_TOK: u64 = u64::MAX;
const SOCK_EVENTS: u32 = (libc::EPOLLIN | libc::EPOLLOUT | libc::EPOLLRDHUP | libc::EPOLLET) as u32;

fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO)
}

fn eventfd() -> io::Result<OwnedFd> {
    let fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn drain(fd: RawFd) {
    let mut v = 0;
    unsafe { libc::eventfd_read(fd, &mut v) };
}

/// The agent's registered rings. `keep` holds the guest memory mapping the
/// pointers point into; they were validated against it at registration.
pub struct Table {
    _keep: Arc<dyn Send + Sync>,
    ctl: *mut u8,
    rings: Vec<*mut u8>,
    in_use: Vec<AtomicBool>,
}

// SAFETY: the pointers refer to guest memory kept mapped by `_keep`; ring
// accesses are atomic or validated (the guest may write concurrently anyway).
unsafe impl Send for Table {}
unsafe impl Sync for Table {}

impl Table {
    pub fn new(keep: Arc<dyn Send + Sync>, ctl: *mut u8, rings: Vec<*mut u8>) -> Self {
        let in_use = (0..rings.len() / 2).map(|_| AtomicBool::new(false)).collect();
        Table { _keep: keep, ctl, rings, in_use }
    }

    /// Binds `slot` to a connection, unless it is out of range or taken.
    pub fn attach(self: &Arc<Self>, slot: u16) -> Option<Rings> {
        let i = slot as usize;
        let flag = self.in_use.get(i)?;
        if flag.swap(true, Ordering::AcqRel) {
            return None;
        }
        // SAFETY: see Table.
        unsafe {
            let ctl = self.ctl.add(i * SLOT_CTL) as *const SlotCtl;
            let g2h = Ring::new(&(*ctl).g2h, self.rings[2 * i]);
            let h2g = Ring::new(&(*ctl).h2g, self.rings[2 * i + 1]);
            Some(Rings { table: self.clone(), idx: i, ctl, tx: Consumer::new(g2h), rx: Producer::new(h2g) })
        }
    }
}

/// A connection's rings: netd consumes guest->host and produces host->guest.
/// Dropping it hands the slot back to the agent.
pub struct Rings {
    table: Arc<Table>,
    idx: usize,
    ctl: *const SlotCtl,
    tx: Consumer,
    rx: Producer,
}

// SAFETY: see Table; a slot's rings are used by one thread at a time.
unsafe impl Send for Rings {}

impl Drop for Rings {
    fn drop(&mut self) {
        // SAFETY: see Table. This is netd's last access to the slot.
        unsafe { (*self.ctl).release() };
        self.table.in_use[self.idx].store(false, Ordering::Release);
    }
}

/// A host socket relayed through a slot's rings.
struct Stream {
    sock: OwnedFd,
    rings: Rings,
    readable: bool,
    writable: bool,
    sock_eof: bool,
    wr_shut: bool,
    /// The agent is gone: only flush what it left in the guest->host ring.
    closing: bool,
    last_work: Instant,
}

impl Stream {
    /// Moves payload between the socket and the rings until both directions
    /// block. With `arm`, it then asks the agent for doorbells where a ring
    /// is the obstacle. Returns (moved data, agent must be woken); it returns
    /// as soon as the agent must be woken, possibly with work left, so that
    /// the agent works on the ring while this stream is pumped again.
    fn pump(&mut self, stats: &Stats, arm: bool) -> io::Result<(bool, bool)> {
        let fd = self.sock.as_raw_fd();
        let (tx, rx) = (&mut self.rings.tx, &mut self.rings.rx);
        let mut iov = [libc::iovec { iov_base: std::ptr::null_mut(), iov_len: 0 }; 2];
        let mut moved = false;
        loop {
            while self.writable && !self.wr_shut {
                let (k, n) = tx.data_iov(&mut iov, CHUNK)?;
                if n == 0 {
                    if tx.finished()? {
                        unsafe { libc::shutdown(fd, libc::SHUT_WR) };
                        self.wr_shut = true;
                    }
                    break;
                }
                let w = unsafe { libc::writev(fd, iov.as_ptr(), k as i32) };
                if w < 0 {
                    match errno() {
                        libc::EINTR => continue,
                        libc::EAGAIN => self.writable = false,
                        e => return Err(io::Error::from_raw_os_error(e)),
                    }
                    break;
                }
                stats.tx_bytes.fetch_add(w as u64, Ordering::Relaxed);
                moved = true;
                if (w as usize) < n {
                    self.writable = false;
                }
                if tx.consume(w as usize) {
                    return Ok((true, true));
                }
            }
            while self.readable && !self.sock_eof && !self.closing {
                let (k, n) = rx.free_iov(&mut iov, CHUNK)?;
                if n == 0 {
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
                moved = true;
                if r == 0 {
                    self.sock_eof = true;
                    if rx.close() {
                        return Ok((true, true));
                    }
                    break;
                }
                stats.rx_bytes.fetch_add(r as u64, Ordering::Relaxed);
                if (r as usize) < n {
                    self.readable = false;
                }
                if rx.commit(r as usize) {
                    return Ok((true, true));
                }
            }
            if !arm {
                return Ok((moved, false));
            }
            // Out of ring data (or space) with the socket still ready: ask the
            // agent for a doorbell, unless it raced us and there is work again.
            let mut again = false;
            if self.writable && !self.wr_shut && !tx.wait()? {
                again = true;
            }
            if self.readable && !self.sock_eof && !self.closing && !rx.wait()? {
                again = true;
            }
            if !again {
                return Ok((moved, false));
            }
        }
    }

    /// After the agent left: nothing more will reach the socket.
    fn flushed(&self) -> bool {
        self.closing && (self.wr_shut || !matches!(self.rings.tx.avail(), Ok(n) if n > 0))
    }
}

enum Cmd {
    Add(u64, OwnedFd, Rings),
    /// The agent rang the doorbell.
    Kick(u64),
    /// The agent closed its end: flush, then release.
    Close(u64),
    /// Reset: release now.
    Drop(u64),
    Stop,
}

pub enum Event {
    /// Wake the agent (send it a doorbell byte).
    Bell(u64),
    /// The stream failed and is gone; reset the vsock connection.
    Reset(u64),
}

struct Inbox {
    cmds: Mutex<Vec<Cmd>>,
    efd: OwnedFd,
}

impl Inbox {
    fn send(&self, c: Cmd) {
        self.cmds.lock().unwrap().push(c);
        unsafe { libc::eventfd_write(self.efd.as_raw_fd(), 1) };
    }
}

struct Outbox {
    events: Mutex<Vec<Event>>,
    efd: OwnedFd,
}

impl Outbox {
    fn send(&self, e: Event) {
        self.events.lock().unwrap().push(e);
        unsafe { libc::eventfd_write(self.efd.as_raw_fd(), 1) };
    }
}

#[derive(Default)]
pub struct Stats {
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub busy_polls: AtomicU64,
    pub wakeups: AtomicU64,
}

impl Stats {
    /// (tx_bytes, rx_bytes, busy_polls, wakeups) since the last call.
    pub fn take(&self) -> (u64, u64, u64, u64) {
        let t = |a: &AtomicU64| a.swap(0, Ordering::Relaxed);
        (t(&self.tx_bytes), t(&self.rx_bytes), t(&self.busy_polls), t(&self.wakeups))
    }
}

struct Worker {
    inbox: Arc<Inbox>,
    thread: Option<JoinHandle<()>>,
}

/// Worker threads; streams are assigned round robin.
pub struct Pool {
    workers: Vec<Worker>,
    next: usize,
    out: Arc<Outbox>,
    pub stats: Arc<Stats>,
}

impl Pool {
    pub fn new(n: usize, busy_poll: Duration) -> io::Result<Self> {
        let out = Arc::new(Outbox { events: Mutex::new(Vec::new()), efd: eventfd()? });
        let stats = Arc::new(Stats::default());
        let mut workers = Vec::new();
        for i in 0..n.max(1) {
            let inbox = Arc::new(Inbox { cmds: Mutex::new(Vec::new()), efd: eventfd()? });
            let ep = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
            if ep < 0 {
                return Err(io::Error::last_os_error());
            }
            let ep = unsafe { OwnedFd::from_raw_fd(ep) };
            epoll_add(ep.as_raw_fd(), inbox.efd.as_raw_fd(), libc::EPOLLIN as u32, INBOX_TOK)?;
            let mut w = Loop { ep, inbox: inbox.clone(), out: out.clone(), stats: stats.clone(), busy_poll, streams: HashMap::new() };
            let thread = thread::Builder::new().name(format!("netd-pump{i}")).spawn(move || w.run())?;
            workers.push(Worker { inbox, thread: Some(thread) });
        }
        Ok(Pool { workers, next: 0, out, stats })
    }

    /// eventfd that becomes readable when `events()` has something.
    pub fn event_fd(&self) -> RawFd {
        self.out.efd.as_raw_fd()
    }

    pub fn events(&self) -> Vec<Event> {
        drain(self.out.efd.as_raw_fd());
        std::mem::take(&mut *self.out.events.lock().unwrap())
    }

    /// Hands a connected socket and its rings to a worker; returns the
    /// worker's index for later commands.
    pub fn add(&mut self, tok: u64, sock: OwnedFd, rings: Rings) -> usize {
        let w = self.next;
        self.next = (self.next + 1) % self.workers.len();
        self.workers[w].inbox.send(Cmd::Add(tok, sock, rings));
        w
    }

    pub fn kick(&self, w: usize, tok: u64) {
        self.workers[w].inbox.send(Cmd::Kick(tok));
    }

    pub fn close(&self, w: usize, tok: u64) {
        self.workers[w].inbox.send(Cmd::Close(tok));
    }

    pub fn drop_stream(&self, w: usize, tok: u64) {
        self.workers[w].inbox.send(Cmd::Drop(tok));
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        for w in &self.workers {
            w.inbox.send(Cmd::Stop);
        }
        for w in &mut self.workers {
            if let Some(t) = w.thread.take() {
                let _ = t.join();
            }
        }
    }
}

fn epoll_add(ep: RawFd, fd: RawFd, events: u32, tok: u64) -> io::Result<()> {
    let mut ev = libc::epoll_event { events, u64: tok };
    if unsafe { libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, fd, &mut ev) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

struct Loop {
    ep: OwnedFd,
    inbox: Arc<Inbox>,
    out: Arc<Outbox>,
    stats: Arc<Stats>,
    busy_poll: Duration,
    streams: HashMap<u64, Stream>,
}

impl Loop {
    fn run(&mut self) {
        // Streams to pump: `ready` after an event, `active` while busy-polled.
        let mut ready = HashSet::new();
        let mut active = HashSet::new();
        let mut evs = [libc::epoll_event { events: 0, u64: 0 }; 64];
        loop {
            let timeout = if active.is_empty() { -1 } else { 0 };
            let n = unsafe { libc::epoll_wait(self.ep.as_raw_fd(), evs.as_mut_ptr(), evs.len() as i32, timeout) };
            if timeout != 0 {
                self.stats.wakeups.fetch_add(1, Ordering::Relaxed);
            }
            for e in &evs[..n.max(0) as usize] {
                let (ev, tok) = (e.events, e.u64);
                if tok == INBOX_TOK {
                    drain(self.inbox.efd.as_raw_fd());
                    let cmds = std::mem::take(&mut *self.inbox.cmds.lock().unwrap());
                    for c in cmds {
                        match c {
                            Cmd::Add(tok, sock, rings) => {
                                if epoll_add(self.ep.as_raw_fd(), sock.as_raw_fd(), SOCK_EVENTS, tok).is_err() {
                                    self.out.send(Event::Reset(tok));
                                    continue;
                                }
                                let s = Stream {
                                    sock,
                                    rings,
                                    readable: true,
                                    writable: true,
                                    sock_eof: false,
                                    wr_shut: false,
                                    closing: false,
                                    last_work: Instant::now(),
                                };
                                self.streams.insert(tok, s);
                                ready.insert(tok);
                            }
                            Cmd::Kick(tok) => {
                                ready.insert(tok);
                            }
                            Cmd::Close(tok) => {
                                if let Some(s) = self.streams.get_mut(&tok) {
                                    s.closing = true;
                                    ready.insert(tok);
                                }
                            }
                            Cmd::Drop(tok) => {
                                self.streams.remove(&tok);
                            }
                            Cmd::Stop => return,
                        }
                    }
                    continue;
                }
                let Some(s) = self.streams.get_mut(&tok) else { continue };
                let hup = (libc::EPOLLERR | libc::EPOLLHUP) as u32;
                if ev & (libc::EPOLLIN as u32 | libc::EPOLLRDHUP as u32 | hup) != 0 {
                    s.readable = true;
                }
                if ev & (libc::EPOLLOUT as u32 | hup) != 0 {
                    s.writable = true;
                }
                ready.insert(tok);
            }
            if !active.is_empty() {
                self.stats.busy_polls.fetch_add(1, Ordering::Relaxed);
            }
            ready.extend(active.iter().copied());
            for tok in ready.drain() {
                let Some(s) = self.streams.get_mut(&tok) else {
                    active.remove(&tok);
                    continue;
                };
                let arm = s.last_work.elapsed() >= self.busy_poll;
                match s.pump(&self.stats, arm) {
                    Ok((moved, bell)) => {
                        if bell && !s.closing {
                            self.out.send(Event::Bell(tok));
                        }
                        if s.flushed() {
                            self.streams.remove(&tok);
                            active.remove(&tok);
                        } else if moved || !arm {
                            // Keep polling until it has been idle for a full
                            // window; only then are its wait flags armed.
                            if moved {
                                s.last_work = Instant::now();
                            }
                            active.insert(tok);
                        } else {
                            active.remove(&tok);
                        }
                    }
                    Err(_) => {
                        self.streams.remove(&tok);
                        active.remove(&tok);
                        self.out.send(Event::Reset(tok));
                    }
                }
            }
        }
    }
}
