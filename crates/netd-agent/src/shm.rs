//! Guest side of the shared-memory data path (see netd_common::shm).
//!
//! The rings live in hugepages: they are never swapped or moved, so their
//! guest-physical addresses, read once from /proc/self/pagemap, stay valid
//! for netd, which maps all guest RAM.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::fs::FileExt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use netd_common::proto::{self, Frame, FrameReader, ShmRegion};
use netd_common::shm::{CHUNK, Consumer, HUGEPAGE, NO_SLOT, Producer, Ring, SLOT_CTL, SlotCtl};

static SPIN_US: AtomicU64 = AtomicU64::new(50);

/// Per-relay counters, logged when a relay ends if NETD_STATS is set.
#[derive(Default, Debug)]
struct Counters {
    reads: u64,
    bytes_in: u64,
    /// readv found the ring full / the application socket empty.
    ring_full: u64,
    app_empty: u64,
    writes: u64,
    bytes_out: u64,
    app_full: u64,
    spin_hits: u64,
    sleeps: u64,
}

/// How long a relay busy-polls for new work before it sleeps (0 = never).
pub fn set_spin_us(us: u64) {
    SPIN_US.store(us, Ordering::Relaxed);
}

pub struct Region {
    ctl: *mut u8,
    rings: Vec<*mut u8>,
    msg: ShmRegion,
    used: Mutex<Vec<bool>>,
    /// netd accepted the registration and it is still alive.
    live: AtomicBool,
    /// Bumped on every registration. netd drops all slot bindings when it
    /// loses a registration, so slots claimed under an older one are free on
    /// its side.
    generation: AtomicU64,
    /// Each slot's stream to netd (see proto::Frame), for the current registration.
    streams: Mutex<Vec<Arc<OwnedFd>>>,
    next_id: AtomicU32,
}

// SAFETY: the hugepage mapping is never unmapped; slot ownership is tracked
// by `used`, and the shared control fields are atomics.
unsafe impl Send for Region {}
unsafe impl Sync for Region {}

fn meminfo(key: &str) -> io::Result<usize> {
    let s = fs::read_to_string("/proc/meminfo")?;
    s.lines()
        .find_map(|l| l.strip_prefix(key)?.strip_prefix(':')?.split_whitespace().next()?.parse().ok())
        .ok_or_else(|| io::Error::other(format!("no {key} in /proc/meminfo")))
}

/// Makes sure `n` free 2 MiB hugepages exist, growing the pool if needed.
fn reserve_hugepages(n: usize) -> io::Result<()> {
    if meminfo("Hugepagesize")? * 1024 != HUGEPAGE {
        return Err(io::Error::other("default hugepage size is not 2 MiB"));
    }
    let free = meminfo("HugePages_Free")?;
    if free < n {
        let total: usize = fs::read_to_string("/proc/sys/vm/nr_hugepages")?.trim().parse().map_err(io::Error::other)?;
        fs::write("/proc/sys/vm/nr_hugepages", (total + n - free).to_string())?;
        if meminfo("HugePages_Free")? < n {
            return Err(io::Error::other(format!("could not reserve {n} hugepages")));
        }
    }
    Ok(())
}

fn gpa(pagemap: &File, va: usize) -> io::Result<u64> {
    let mut b = [0u8; 8];
    pagemap.read_exact_at(&mut b, (va / 4096 * 8) as u64)?;
    let e = u64::from_le_bytes(b);
    let pfn = e & ((1 << 55) - 1);
    if e >> 63 == 0 || pfn == 0 {
        return Err(io::Error::other("page frame not visible in pagemap (needs root)"));
    }
    Ok(pfn * 4096)
}

impl Region {
    pub fn new(slots: usize) -> io::Result<Self> {
        let pages = 1 + 2 * slots;
        reserve_hugepages(pages)?;
        let len = pages * HUGEPAGE;
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS | libc::MAP_HUGETLB | libc::MAP_POPULATE,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let base = p.cast::<u8>();
        let pagemap = File::open("/proc/self/pagemap")?;
        let mut gpas = Vec::with_capacity(pages);
        for i in 0..pages {
            gpas.push(gpa(&pagemap, base as usize + i * HUGEPAGE)?);
        }
        // SAFETY: every page lies inside the mapping created above.
        let rings = (1..pages).map(|i| unsafe { base.add(i * HUGEPAGE) }).collect();
        Ok(Region {
            ctl: base,
            rings,
            msg: ShmRegion { ctl_gpa: gpas[0], ring_gpas: gpas[1..].to_vec() },
            used: Mutex::new(vec![false; slots]),
            live: AtomicBool::new(false),
            generation: AtomicU64::new(0),
            streams: Mutex::new(Vec::new()),
            next_id: AtomicU32::new(0),
        })
    }

    fn ctl(&self, i: usize) -> &SlotCtl {
        // SAFETY: i < slots, and SLOT_CTL * slots fits the control hugepage.
        unsafe { &*(self.ctl.add(i * SLOT_CTL) as *const SlotCtl) }
    }

    /// A slot neither this agent nor netd is using, ready for a new connection.
    pub fn claim(self: &Arc<Self>) -> Option<Slot> {
        if !self.live.load(Ordering::Acquire) {
            return None;
        }
        let streams = self.streams.lock().unwrap();
        let mut used = self.used.lock().unwrap();
        let i = (0..streams.len()).find(|&i| !used[i] && !self.ctl(i).host_busy())?;
        used[i] = true;
        self.ctl(i).claim();
        Some(Slot {
            region: self.clone(),
            idx: i,
            generation: self.generation.load(Ordering::Acquire),
            stream: streams[i].clone(),
        })
    }

    /// Registers with netd and keeps the registration stream open; re-registers
    /// if netd goes away. Returns once the first attempt has finished.
    pub fn register(self: &Arc<Self>, connect: impl Fn() -> io::Result<OwnedFd> + Send + 'static) {
        let me = self.clone();
        let first = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let f2 = first.clone();
        std::thread::spawn(move || {
            loop {
                let r = me.register_once(&connect, &f2);
                me.live.store(false, Ordering::Release);
                done(&f2);
                match r {
                    Err(e) if e.raw_os_error() == Some(libc::EPROTONOSUPPORT) => {
                        eprintln!("netd-agent: netd does not support shared rings");
                        return;
                    }
                    Err(e) => eprintln!("netd-agent: shared rings: {e}"),
                    Ok(()) => eprintln!("netd-agent: shared-ring registration closed"),
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        });
        let (m, cv) = &*first;
        let _ = cv.wait_timeout_while(m.lock().unwrap(), Duration::from_secs(5), |d| !*d);
    }

    fn register_once(&self, connect: &impl Fn() -> io::Result<OwnedFd>, first: &(Mutex<bool>, std::sync::Condvar)) -> io::Result<()> {
        let mut s = File::from(connect()?);
        s.write_all(&self.msg.encode())?;
        match proto::read_status(&mut s)? {
            (0, _) => {}
            (e, _) => return Err(io::Error::from_raw_os_error(e)),
        }
        let n = self.used.lock().unwrap().len();
        let mut streams = Vec::with_capacity(n);
        for i in 0..n {
            let mut f = File::from(connect()?);
            f.write_all(&proto::encode_slot(i as u16))?;
            match proto::read_status(&mut f)? {
                (0, _) => {}
                (e, _) => return Err(io::Error::from_raw_os_error(e)),
            }
            set_nonblocking(f.as_raw_fd(), true)?;
            streams.push(Arc::new(OwnedFd::from(f)));
        }
        // A new registration starts clean on netd's side: slots that only
        // netd still held (before it restarted) are free again.
        {
            let used = self.used.lock().unwrap();
            for (i, u) in used.iter().enumerate() {
                if !u {
                    self.ctl(i).release();
                }
            }
        }
        self.generation.fetch_add(1, Ordering::AcqRel);
        *self.streams.lock().unwrap() = streams;
        self.live.store(true, Ordering::Release);
        eprintln!("netd-agent: shared rings registered ({} slots)", self.msg.ring_gpas.len() / 2);
        done(first);
        // netd never sends on this stream; it ends when netd drops it.
        let mut b = [0u8; 64];
        let res = loop {
            match s.read(&mut b) {
                Ok(0) => break Ok(()),
                Ok(_) => {}
                Err(e) => break Err(e),
            }
        };
        self.streams.lock().unwrap().clear();
        res
    }
}

fn done(first: &(Mutex<bool>, std::sync::Condvar)) {
    *first.0.lock().unwrap() = true;
    first.1.notify_all();
}

pub struct Slot {
    region: Arc<Region>,
    idx: usize,
    generation: u64,
    stream: Arc<OwnedFd>,
}

impl Slot {
    pub fn index(&self) -> u16 {
        self.idx as u16
    }

    /// (guest->host producer, host->guest consumer)
    fn rings(&self) -> (Producer, Consumer) {
        let c = self.region.ctl(self.idx);
        // SAFETY: control block and rings live in the never-unmapped region.
        unsafe {
            let g2h = Ring::new(&c.g2h, self.region.rings[2 * self.idx]);
            let h2g = Ring::new(&c.h2g, self.region.rings[2 * self.idx + 1]);
            (Producer::new(g2h), Consumer::new(h2g))
        }
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut used = self.region.used.lock().unwrap();
        if self.region.generation.load(Ordering::Acquire) != self.generation {
            self.region.ctl(self.idx).release();
        }
        used[self.idx] = false;
    }
}

/// Picks the slot to offer for a connection, or `NO_SLOT`.
pub fn offer(region: &Option<Arc<Region>>) -> (Option<Slot>, u16) {
    let slot = region.as_ref().and_then(|r| r.claim());
    let idx = slot.as_ref().map_or(NO_SLOT, Slot::index);
    (slot, idx)
}

fn set_nonblocking(fd: RawFd, on: bool) -> io::Result<()> {
    unsafe {
        let fl = libc::fcntl(fd, libc::F_GETFL);
        if fl < 0 {
            return Err(io::Error::last_os_error());
        }
        let fl = if on { fl | libc::O_NONBLOCK } else { fl & !libc::O_NONBLOCK };
        if libc::fcntl(fd, libc::F_SETFL, fl) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Result of one non-blocking readv/writev.
enum Io {
    Done(usize),
    Blocked,
}

fn io_result(n: isize) -> io::Result<Io> {
    if n >= 0 {
        return Ok(Io::Done(n as usize));
    }
    match io::Error::last_os_error() {
        e if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::Interrupted => Ok(Io::Blocked),
        e => Err(e),
    }
}

/// Writes a whole frame to a non-blocking stream.
fn send(v: RawFd, f: Frame) -> io::Result<()> {
    let mut b = Vec::with_capacity(32);
    f.encode(&mut b);
    let mut off = 0;
    while off < b.len() {
        match io_result(unsafe { libc::write(v, b[off..].as_ptr().cast(), b.len() - off) })? {
            Io::Done(n) => off += n,
            Io::Blocked => {
                let mut p = libc::pollfd { fd: v, events: libc::POLLOUT, revents: 0 };
                unsafe { libc::poll(&mut p, 1, -1) };
            }
        }
    }
    Ok(())
}

/// Relays an outbound guest TCP connection to `dst` through the slot. The
/// application is already connected (to us), so nothing waits for netd:
/// payload goes into the ring while netd connects, and a Fail frame resets
/// the connection if netd could not.
pub fn relay_out(tcp: OwnedFd, slot: Slot, dst: SocketAddr) -> io::Result<()> {
    let v = slot.stream.as_raw_fd();
    let id = slot.region.next_id.fetch_add(1, Ordering::Relaxed);
    pump(tcp, v, &slot, Some((id, dst)))
}

/// Relays a host port forward through the slot; `vs` is the connection's
/// own stream, used only for doorbells, and closing it ends the connection.
pub fn relay_in(tcp: OwnedFd, vs: OwnedFd, slot: Slot) -> io::Result<()> {
    set_nonblocking(vs.as_raw_fd(), true)?;
    pump(tcp, vs.as_raw_fd(), &slot, None)
}

/// `open`: the connection on a slot stream, whose Fail frame ends the relay.
fn pump(tcp: OwnedFd, v: RawFd, slot: &Slot, open: Option<(u32, SocketAddr)>) -> io::Result<()> {
    let t = tcp.as_raw_fd();
    let (mut tx, mut rx) = slot.rings();
    let mut cnt = Counters::default();
    let start = Instant::now();
    let initial = set_nonblocking(t, true).and_then(|()| {
        if open.is_some() { read_initial(t, &mut tx, &mut cnt) } else { Ok(false) }
    });
    if let Some((id, dst)) = open {
        // Even when the initial read failed, netd must see Open and Reset
        // so it can release the claimed slot.
        send(v, Frame::Open { id, dst })?;
    }
    let res = initial.and_then(|app_eof| pump_loop(t, v, &mut tx, &mut rx, open.map(|o| o.0), app_eof, &mut cnt));
    if open.is_some() {
        send(v, if res.is_ok() { Frame::Close } else { Frame::Reset })?;
    }
    if std::env::var_os("NETD_STATS").is_some() && cnt.bytes_in + cnt.bytes_out > 1 << 20 {
        eprintln!("netd-agent: relay {:?} {cnt:?}", start.elapsed());
    }
    res
}

/// Publish any already queued data before Open wakes netd. Never wait here:
/// server-first protocols must connect even when the application sent nothing.
fn read_initial(t: RawFd, tx: &mut Producer, cnt: &mut Counters) -> io::Result<bool> {
    let mut iov = [libc::iovec { iov_base: std::ptr::null_mut(), iov_len: 0 }; 2];
    let (k, n) = tx.free_iov(&mut iov, CHUNK)?;
    if n == 0 {
        return Ok(false);
    }
    match io_result(unsafe { libc::readv(t, iov.as_ptr(), k as i32) })? {
        Io::Done(0) => {
            tx.close();
            Ok(true)
        }
        Io::Done(n) => {
            cnt.reads += 1;
            cnt.bytes_in += n as u64;
            tx.commit(n);
            Ok(false)
        }
        Io::Blocked => Ok(false),
    }
}

fn pump_loop(t: RawFd, v: RawFd, tx: &mut Producer, rx: &mut Consumer, id: Option<u32>, mut app_eof: bool, cnt: &mut Counters) -> io::Result<()> {
    let iov = &mut [libc::iovec { iov_base: std::ptr::null_mut(), iov_len: 0 }; 2];
    let mut scratch = [0u8; 256];
    let mut frames = FrameReader::default();
    let mut wr_shut = false;
    loop {
        // Doorbells, and netd's verdict on this connection. Bells and Fail
        // frames left over from the slot's earlier connections are ignored.
        // netd keeps the stream open while the agent uses it, so EOF here
        // means it went away.
        loop {
            match io_result(unsafe { libc::read(v, scratch.as_mut_ptr().cast(), scratch.len()) })? {
                Io::Done(0) => return Err(io::ErrorKind::ConnectionReset.into()),
                Io::Done(n) => frames.feed(&scratch[..n], |f| match f {
                    Frame::Fail { id: got, errno } if Some(got) == id => Err(io::Error::from_raw_os_error(errno)),
                    Frame::Bell | Frame::Fail { .. } => Ok(()),
                    _ => Err(io::Error::other("unexpected frame from netd")),
                })?,
                Io::Blocked => break,
            }
        }
        // application -> ring
        let mut want_in = false;
        let mut eof_bell = false;
        while !app_eof {
            let (k, n) = tx.free_iov(iov, CHUNK)?;
            if n == 0 {
                cnt.ring_full += 1;
                break;
            }
            match io_result(unsafe { libc::readv(t, iov.as_ptr(), k as i32) })? {
                Io::Done(0) => {
                    app_eof = true;
                    eof_bell = tx.close();
                }
                Io::Done(r) => {
                    cnt.reads += 1;
                    cnt.bytes_in += r as u64;
                    if tx.commit(r) {
                        doorbell(v);
                    }
                    if r < n {
                        cnt.app_empty += 1;
                        want_in = true;
                        break;
                    }
                }
                Io::Blocked => {
                    cnt.app_empty += 1;
                    want_in = true;
                    break;
                }
            }
        }

        // ring -> application
        let mut want_out = false;
        while !wr_shut {
            let (k, n) = rx.data_iov(iov, CHUNK)?;
            if n == 0 {
                if rx.finished()? {
                    unsafe { libc::shutdown(t, libc::SHUT_WR) };
                    wr_shut = true;
                }
                break;
            }
            match io_result(unsafe { libc::writev(t, iov.as_ptr(), k as i32) })? {
                Io::Done(w) => {
                    cnt.writes += 1;
                    cnt.bytes_out += w as u64;
                    if rx.consume(w) {
                        doorbell(v);
                    }
                    if w < n {
                        cnt.app_full += 1;
                        want_out = true;
                        break;
                    }
                }
                Io::Blocked => {
                    cnt.app_full += 1;
                    want_out = true;
                    break;
                }
            }
        }

        if app_eof && wr_shut {
            // netd flushes whatever is left in the guest->host ring once the
            // caller tells it (Close, or closing a forward's stream), which
            // also stands in for the EOF doorbell.
            return Ok(());
        }
        if eof_bell {
            doorbell(v);
        }

        let tev = if want_in { libc::POLLIN } else { 0 } | if want_out { libc::POLLOUT } else { 0 };
        let ring_in = !app_eof && !want_in;
        let ring_out = !wr_shut && !want_out;
        // Spinning only pays off while waiting for data (request/response).
        // A full ring or application socket means bulk transfer: spinning
        // would take CPU from whoever has to make room.
        let bulk = ring_in || want_out;
        if !bulk && spin(rx, ring_out, t, tev)? {
            cnt.spin_hits += 1;
            continue;
        }

        // Nothing to do without blocking: ask netd for doorbells where a ring
        // is the obstacle, then sleep unless that raced with new work.
        let mut sleep = true;
        if ring_in && !tx.wait()? {
            sleep = false;
        }
        if ring_out && !rx.wait()? {
            sleep = false;
        }
        if !sleep {
            continue;
        }
        cnt.sleeps += 1;
        let mut pfd = [
            libc::pollfd { fd: if tev != 0 { t } else { -1 }, events: tev, revents: 0 },
            libc::pollfd { fd: v, events: libc::POLLIN, revents: 0 },
        ];
        if unsafe { libc::poll(pfd.as_mut_ptr(), 2, -1) } < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(io::Error::last_os_error());
        }
        if pfd[0].revents & libc::POLLERR != 0 {
            return Err(io::ErrorKind::ConnectionReset.into());
        }
    }
}

/// Wakes netd as soon as it is waiting for this ring, so that it works on
/// the ring while this side carries on with the next chunk.
fn doorbell(v: RawFd) {
    // EAGAIN means netd has unread doorbells and will look anyway.
    unsafe { libc::write(v, [0u8].as_ptr().cast(), 1) };
    // Before Linux 6.11, virtio-vsock hands every packet to a kworker on this
    // CPU, which would only get to run once this thread blocks, i.e. after it
    // filled or drained the whole ring.
    unsafe { libc::sched_yield() };
}

/// Busy-polls the rings (and the application socket) for a short while.
/// Request/response traffic usually gets its answer within microseconds;
/// catching it here saves netd a doorbell and the guest an interrupt and a
/// wakeup. Returns true if there is work.
fn spin(rx: &Consumer, ring_out: bool, t: RawFd, tev: libc::c_short) -> io::Result<bool> {
    let budget = Duration::from_micros(SPIN_US.load(Ordering::Relaxed));
    let start = Instant::now();
    while start.elapsed() < budget {
        if ring_out && (rx.avail()? > 0 || rx.finished()?) {
            return Ok(true);
        }
        let mut pfd = libc::pollfd { fd: t, events: tev, revents: 0 };
        if tev != 0 && unsafe { libc::poll(&mut pfd, 1, 0) } > 0 {
            return Ok(true);
        }
        // Not a pause: whatever this thread just sent on vsock (request,
        // status, doorbell) waits in a kworker on this CPU (see doorbell()).
        unsafe { libc::sched_yield() };
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;
    use netd_common::shm::RING_SIZE;

    #[test]
    fn initial_read_handles_empty_data_and_half_close() {
        // All SlotCtl fields are atomics, for which zero is a valid initial value.
        let ctl: Box<SlotCtl> = Box::new(unsafe { std::mem::zeroed() });
        ctl.claim();
        let mut data = vec![0u8; RING_SIZE];
        let ring = unsafe { Ring::new(&ctl.g2h, data.as_mut_ptr()) };
        let mut tx = Producer::new(ring);
        let mut rx = Consumer::new(ring);
        let (mut app, agent) = UnixStream::pair().unwrap();
        agent.set_nonblocking(true).unwrap();
        let mut cnt = Counters::default();

        assert!(!read_initial(agent.as_raw_fd(), &mut tx, &mut cnt).unwrap());
        assert_eq!(rx.avail().unwrap(), 0);

        app.write_all(b"request").unwrap();
        assert!(!read_initial(agent.as_raw_fd(), &mut tx, &mut cnt).unwrap());
        let mut iov = [libc::iovec { iov_base: std::ptr::null_mut(), iov_len: 0 }; 2];
        let (_, n) = rx.data_iov(&mut iov, CHUNK).unwrap();
        assert_eq!(n, 7);
        assert_eq!(unsafe { std::slice::from_raw_parts(iov[0].iov_base.cast::<u8>(), n) }, b"request");
        rx.consume(n);

        app.shutdown(Shutdown::Write).unwrap();
        assert!(read_initial(agent.as_raw_fd(), &mut tx, &mut cnt).unwrap());
        assert!(rx.finished().unwrap());
    }
}
