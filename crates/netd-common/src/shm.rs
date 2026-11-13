//! Shared-memory byte rings between netd-agent and netd.
//!
//! The guest agent allocates hugepages, registers their guest-physical
//! addresses with netd (which maps all guest RAM as the vhost-user backend)
//! and from then on offloaded connections that hold a *slot* move their
//! payload through two single-producer/single-consumer rings instead of
//! vsock packets:
//!
//! ```text
//! control hugepage: SlotCtl[0] SlotCtl[1] ...   (SLOT_CTL bytes each)
//! ring hugepages:   g2h ring + h2g ring per slot (RING_SIZE bytes each)
//! ```
//!
//! Positions are free-running u64 byte counters. A side that runs out of
//! work sets its wait flag and re-checks; the other side clears the flag and
//! rings the doorbell (a `Frame::Bell` on the slot's vsock stream) only when
//! it was set. EOF travels in the ring as well, so the stream stays usable
//! for doorbells in both directions until the connection ends.
//!
//! The host treats everything in shared memory as untrusted: positions are
//! validated before use and all accesses stay inside the registered ring.

use std::io;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering, fence};

pub const HUGEPAGE: usize = 2 << 20;
pub const RING_SIZE: usize = HUGEPAGE;
/// Largest guest-to-host transfer between ring updates. Committing in pieces
/// lets the peer work concurrently instead of waiting for a whole ring.
pub const CHUNK: usize = RING_SIZE / 8;
/// Larger batches amortize host socket reads during host-to-guest transfers.
pub const HOST_TO_GUEST_CHUNK: usize = RING_SIZE / 2;
/// A waiting producer is only woken once this much space is free, so a full
/// ring costs one doorbell per half turn rather than one per chunk, while the
/// consumer keeps draining the other half.
pub const WAKE_SPACE: usize = RING_SIZE / 2;
pub const SLOT_CTL: usize = 1024;
pub const MAX_SLOTS: usize = HUGEPAGE / SLOT_CTL;
pub const NO_SLOT: u16 = u16::MAX;

#[repr(C, align(64))]
struct Line<T>(T);

#[repr(C)]
pub struct RingCtl {
    tail: Line<AtomicU64>,
    head: Line<AtomicU64>,
    cons_wait: Line<AtomicU32>,
    prod_wait: Line<AtomicU32>,
    eof: Line<AtomicU32>,
}

/// Per-slot control block at `ctl_base + slot * SLOT_CTL`.
#[repr(C)]
pub struct SlotCtl {
    pub g2h: RingCtl,
    pub h2g: RingCtl,
    /// Set by the agent when it hands the slot to netd; cleared by netd when
    /// it will never touch the slot again.
    pub host_busy: AtomicU32,
}

const _: () = assert!(size_of::<SlotCtl>() <= SLOT_CTL);

impl RingCtl {
    fn reset(&self) {
        self.tail.0.store(0, Ordering::Relaxed);
        self.head.0.store(0, Ordering::Relaxed);
        self.cons_wait.0.store(0, Ordering::Relaxed);
        self.prod_wait.0.store(0, Ordering::Relaxed);
        self.eof.0.store(0, Ordering::Relaxed);
    }
}

impl SlotCtl {
    /// Prepares a free slot for a new connection (agent side).
    pub fn claim(&self) {
        self.g2h.reset();
        self.h2g.reset();
        self.host_busy.store(1, Ordering::Release);
    }

    pub fn host_busy(&self) -> bool {
        self.host_busy.load(Ordering::Acquire) != 0
    }

    /// netd's last access to the slot.
    pub fn release(&self) {
        self.host_busy.store(0, Ordering::Release);
    }
}

fn corrupt() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "shared ring corrupted")
}

/// One ring: its control block and RING_SIZE bytes of data.
#[derive(Clone, Copy)]
pub struct Ring {
    ctl: *const RingCtl,
    data: *mut u8,
}

// SAFETY: the pointers refer to shared memory that outlives the ring's users;
// all control fields are atomics.
unsafe impl Send for Ring {}

impl Ring {
    /// # Safety
    /// `ctl` must point to a `RingCtl` and `data` to `RING_SIZE` bytes, both
    /// valid (and 64-byte aligned for `ctl`) while the ring is in use.
    pub unsafe fn new(ctl: *const RingCtl, data: *mut u8) -> Self {
        Ring { ctl, data }
    }

    fn ctl(&self) -> &RingCtl {
        // SAFETY: guaranteed by `new`.
        unsafe { &*self.ctl }
    }

    /// Up to two iovecs covering `len` bytes starting at position `pos`.
    fn iov(&self, pos: u64, len: usize, out: &mut [libc::iovec; 2]) -> usize {
        if len == 0 {
            return 0;
        }
        let off = (pos as usize) & (RING_SIZE - 1);
        let first = len.min(RING_SIZE - off);
        // SAFETY: off < RING_SIZE and off + first <= RING_SIZE.
        out[0] = libc::iovec { iov_base: unsafe { self.data.add(off) }.cast(), iov_len: first };
        if first == len {
            return 1;
        }
        out[1] = libc::iovec { iov_base: self.data.cast(), iov_len: len - first };
        2
    }
}

/// Writing end of a ring.
pub struct Producer {
    ring: Ring,
    tail: u64,
}

impl Producer {
    pub fn new(ring: Ring) -> Self {
        Producer { tail: ring.ctl().tail.0.load(Ordering::Relaxed), ring }
    }

    pub fn space(&self) -> io::Result<usize> {
        let used = self.tail.wrapping_sub(self.ring.ctl().head.0.load(Ordering::Acquire));
        if used > RING_SIZE as u64 {
            return Err(corrupt());
        }
        Ok(RING_SIZE - used as usize)
    }

    /// Iovecs for at most `max` bytes of free space; returns (count, bytes).
    pub fn free_iov(&self, out: &mut [libc::iovec; 2], max: usize) -> io::Result<(usize, usize)> {
        let n = self.space()?.min(max);
        Ok((self.ring.iov(self.tail, n, out), n))
    }

    /// Publishes `n` written bytes. Returns true if the consumer must be woken.
    pub fn commit(&mut self, n: usize) -> bool {
        self.tail = self.tail.wrapping_add(n as u64);
        let c = self.ring.ctl();
        c.tail.0.store(self.tail, Ordering::Release);
        fence(Ordering::SeqCst);
        c.cons_wait.0.swap(0, Ordering::Relaxed) != 0
    }

    /// Marks the end of the stream. Returns true if the consumer must be woken.
    pub fn close(&self) -> bool {
        let c = self.ring.ctl();
        c.eof.0.store(1, Ordering::Release);
        fence(Ordering::SeqCst);
        c.cons_wait.0.swap(0, Ordering::Relaxed) != 0
    }

    /// Asks to be woken when WAKE_SPACE is free. Returns false (and withdraws
    /// the request) if it already is.
    pub fn wait(&self) -> io::Result<bool> {
        let c = self.ring.ctl();
        c.prod_wait.0.store(1, Ordering::Relaxed);
        fence(Ordering::SeqCst);
        if self.space()? >= WAKE_SPACE {
            c.prod_wait.0.store(0, Ordering::Relaxed);
            return Ok(false);
        }
        Ok(true)
    }
}

/// Reading end of a ring.
pub struct Consumer {
    ring: Ring,
    head: u64,
}

impl Consumer {
    pub fn new(ring: Ring) -> Self {
        Consumer { head: ring.ctl().head.0.load(Ordering::Relaxed), ring }
    }

    pub fn avail(&self) -> io::Result<usize> {
        let n = self.ring.ctl().tail.0.load(Ordering::Acquire).wrapping_sub(self.head);
        if n > RING_SIZE as u64 {
            return Err(corrupt());
        }
        Ok(n as usize)
    }

    /// Iovecs for at most `max` bytes of readable data; returns (count, bytes).
    pub fn data_iov(&self, out: &mut [libc::iovec; 2], max: usize) -> io::Result<(usize, usize)> {
        let n = self.avail()?.min(max);
        Ok((self.ring.iov(self.head, n, out), n))
    }

    /// Releases `n` read bytes. Returns true if the producer must be woken.
    pub fn consume(&mut self, n: usize) -> bool {
        self.head = self.head.wrapping_add(n as u64);
        let c = self.ring.ctl();
        c.head.0.store(self.head, Ordering::Release);
        fence(Ordering::SeqCst);
        if c.prod_wait.0.load(Ordering::Relaxed) == 0 {
            return false;
        }
        // A corrupt tail counts as no space: the producer is not woken.
        let used = c.tail.0.load(Ordering::Acquire).wrapping_sub(self.head);
        RING_SIZE.saturating_sub(used.min(RING_SIZE as u64) as usize) >= WAKE_SPACE
            && c.prod_wait.0.swap(0, Ordering::Relaxed) != 0
    }

    /// The producer closed the stream and everything has been read.
    pub fn finished(&self) -> io::Result<bool> {
        let eof = self.ring.ctl().eof.0.load(Ordering::Acquire) != 0;
        Ok(eof && self.avail()? == 0)
    }

    /// Asks to be woken when data or EOF arrives. Returns false (and
    /// withdraws the request) if there already is something to do.
    pub fn wait(&self) -> io::Result<bool> {
        let c = self.ring.ctl();
        c.cons_wait.0.store(1, Ordering::Relaxed);
        fence(Ordering::SeqCst);
        if self.avail()? > 0 || c.eof.0.load(Ordering::Acquire) != 0 {
            c.cons_wait.0.store(0, Ordering::Relaxed);
            return Ok(false);
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Mem {
        ctl: Box<SlotCtl>,
        data: Vec<u8>,
    }

    fn ring() -> (Mem, Producer, Consumer) {
        let ctl: Box<SlotCtl> = Box::new(unsafe { std::mem::zeroed() });
        let mut data = vec![0u8; RING_SIZE];
        let r = unsafe { Ring::new(&ctl.g2h, data.as_mut_ptr()) };
        (Mem { ctl, data }, Producer::new(r), Consumer::new(r))
    }

    fn write(p: &mut Producer, bytes: &[u8]) -> usize {
        let mut iov = [libc::iovec { iov_base: std::ptr::null_mut(), iov_len: 0 }; 2];
        let (k, _) = p.free_iov(&mut iov, usize::MAX).unwrap();
        let mut done = 0;
        for v in &iov[..k] {
            let n = v.iov_len.min(bytes.len() - done);
            unsafe { std::ptr::copy_nonoverlapping(bytes[done..].as_ptr(), v.iov_base.cast(), n) };
            done += n;
        }
        p.commit(done);
        done
    }

    fn read(c: &mut Consumer, max: usize) -> Vec<u8> {
        let mut iov = [libc::iovec { iov_base: std::ptr::null_mut(), iov_len: 0 }; 2];
        let (k, _) = c.data_iov(&mut iov, usize::MAX).unwrap();
        let mut out = Vec::new();
        for v in &iov[..k] {
            let n = v.iov_len.min(max - out.len());
            out.extend_from_slice(unsafe { std::slice::from_raw_parts(v.iov_base as *const u8, n) });
        }
        c.consume(out.len());
        out
    }

    #[test]
    fn wraps_around_and_signals() {
        let (_m, mut p, mut c) = ring();
        assert!(c.wait().unwrap());
        let a = vec![7u8; RING_SIZE - 10];
        assert_eq!(write(&mut p, &a), a.len());
        assert_eq!(read(&mut c, RING_SIZE), a);
        // 30 bytes now straddle the end of the buffer.
        let b: Vec<u8> = (0..30).collect();
        assert_eq!(write(&mut p, &b), 30);
        assert_eq!(read(&mut c, 30), b);
        assert!(!p.close());
        assert!(c.finished().unwrap());
    }

    #[test]
    fn full_ring_wakes_producer() {
        let (_m, mut p, mut c) = ring();
        assert_eq!(write(&mut p, &vec![1u8; RING_SIZE + 5]), RING_SIZE);
        assert!(p.wait().unwrap());
        // Below WAKE_SPACE the producer keeps sleeping.
        assert!(!c.consume(1));
        assert!(p.wait().unwrap());
        assert!(c.consume(WAKE_SPACE - 1));
        assert!(!p.wait().unwrap());
    }

    #[test]
    fn rejects_bogus_positions() {
        let (m, p, c) = ring();
        m.ctl.g2h.tail.0.store(RING_SIZE as u64 + 1, Ordering::Relaxed);
        assert!(c.avail().is_err());
        m.ctl.g2h.head.0.store(5, Ordering::Relaxed);
        assert!(p.space().is_err());
        let _ = &m.data;
    }
}
