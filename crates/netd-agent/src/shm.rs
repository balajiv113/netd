//! Guest side of the shared-memory data path (see netd_common::shm).
//!
//! The rings live in hugepages: they are never swapped or moved, so their
//! guest-physical addresses, read once from /proc/self/pagemap, stay valid
//! for netd, which maps all guest RAM.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::fs::FileExt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use netd_common::proto::{self, ShmRegion};
use netd_common::shm::{Consumer, HUGEPAGE, NO_SLOT, Producer, Ring, SLOT_CTL, SlotCtl};

static SPIN_US: AtomicU64 = AtomicU64::new(50);

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
        let mut used = self.used.lock().unwrap();
        let i = (0..used.len()).find(|&i| !used[i] && !self.ctl(i).host_busy())?;
        used[i] = true;
        self.ctl(i).claim();
        Some(Slot { region: self.clone(), idx: i, generation: self.generation.load(Ordering::Acquire) })
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
        self.live.store(true, Ordering::Release);
        eprintln!("netd-agent: shared rings registered ({} slots)", self.msg.ring_gpas.len() / 2);
        done(first);
        // netd never sends on this stream; it ends when netd drops it.
        let mut b = [0u8; 64];
        while s.read(&mut b)? > 0 {}
        Ok(())
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
}

impl Slot {
    pub fn index(&self) -> u16 {
        self.idx as u16
    }

    /// netd did not take the slot.
    pub fn give_back(self) {
        self.region.ctl(self.idx).release();
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

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    unsafe {
        let fl = libc::fcntl(fd, libc::F_GETFL);
        if fl < 0 || libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK) < 0 {
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

/// Relays a guest TCP connection through a slot's rings. `vs` is the
/// connection's vsock stream, used only for doorbells from here on.
pub fn relay(tcp: OwnedFd, vs: OwnedFd, slot: Slot) -> io::Result<()> {
    let (t, v) = (tcp.as_raw_fd(), vs.as_raw_fd());
    set_nonblocking(t)?;
    set_nonblocking(v)?;
    let (mut tx, mut rx) = slot.rings();
    let mut iov = [libc::iovec { iov_base: std::ptr::null_mut(), iov_len: 0 }; 2];
    let mut app_eof = false;
    let mut wr_shut = false;
    let mut scratch = [0u8; 256];
    loop {
        // Doorbells. netd keeps the stream open until the agent is done, so
        // EOF or an error here means the connection was reset.
        loop {
            match unsafe { libc::read(v, scratch.as_mut_ptr().cast(), scratch.len()) } {
                0 => return Err(io::ErrorKind::ConnectionReset.into()),
                n if n > 0 => continue,
                n => match io_result(n)? {
                    Io::Blocked => break,
                    Io::Done(_) => unreachable!(),
                },
            }
        }
        let mut bell = false;

        // application -> ring
        let mut want_in = false;
        while !app_eof {
            let (k, n) = tx.free_iov(&mut iov)?;
            if n == 0 {
                break;
            }
            match io_result(unsafe { libc::readv(t, iov.as_ptr(), k as i32) })? {
                Io::Done(0) => {
                    app_eof = true;
                    bell |= tx.close();
                }
                Io::Done(r) => {
                    bell |= tx.commit(r);
                    if r < n {
                        want_in = true;
                        break;
                    }
                }
                Io::Blocked => {
                    want_in = true;
                    break;
                }
            }
        }

        // ring -> application
        let mut want_out = false;
        while !wr_shut {
            let (k, n) = rx.data_iov(&mut iov)?;
            if n == 0 {
                if rx.finished()? {
                    unsafe { libc::shutdown(t, libc::SHUT_WR) };
                    wr_shut = true;
                }
                break;
            }
            match io_result(unsafe { libc::writev(t, iov.as_ptr(), k as i32) })? {
                Io::Done(w) => {
                    bell |= rx.consume(w);
                    if w < n {
                        want_out = true;
                        break;
                    }
                }
                Io::Blocked => {
                    want_out = true;
                    break;
                }
            }
        }

        if bell {
            // EAGAIN means netd has unread doorbells and will look anyway.
            unsafe { libc::write(v, [0u8].as_ptr().cast(), 1) };
        }
        if app_eof && wr_shut {
            // netd flushes whatever is left in the guest->host ring.
            return Ok(());
        }

        let tev = if want_in { libc::POLLIN } else { 0 } | if want_out { libc::POLLOUT } else { 0 };
        let ring_in = !app_eof && !want_in;
        let ring_out = !wr_shut && !want_out;
        if spin(&tx, &rx, ring_in, ring_out, t, tev)? {
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

/// Busy-polls the rings (and the application socket) for a short while.
/// Request/response traffic usually gets its answer within microseconds;
/// catching it here saves netd a doorbell and the guest an interrupt and a
/// wakeup. Returns true if there is work.
fn spin(tx: &Producer, rx: &Consumer, ring_in: bool, ring_out: bool, t: RawFd, tev: libc::c_short) -> io::Result<bool> {
    let budget = Duration::from_micros(SPIN_US.load(Ordering::Relaxed));
    let start = Instant::now();
    while start.elapsed() < budget {
        if ring_out && (rx.avail()? > 0 || rx.finished()?) || ring_in && tx.space()? > 0 {
            return Ok(true);
        }
        let mut pfd = libc::pollfd { fd: t, events: tev, revents: 0 };
        if tev != 0 && unsafe { libc::poll(&mut pfd, 1, 0) } > 0 {
            return Ok(true);
        }
        std::hint::spin_loop();
    }
    Ok(false)
}
