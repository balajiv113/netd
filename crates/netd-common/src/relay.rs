//! Bidirectional byte relay between two stream sockets.
//!
//! On Linux each direction moves data with splice(2) through a pipe, so the
//! payload never enters userspace. Socket types without splice support fall
//! back to a read/write loop.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::thread;

const CHUNK: usize = 1 << 20;
const FALLBACK_BUF: usize = 256 * 1024;

fn last_err() -> io::Error {
    io::Error::last_os_error()
}

struct Pipe([RawFd; 2]);

impl Drop for Pipe {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0[0]);
            libc::close(self.0[1]);
        }
    }
}

fn new_pipe() -> io::Result<Pipe> {
    let mut p = [0; 2];
    if unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(last_err());
    }
    // Best effort: a bigger pipe means fewer splice calls per megabyte.
    unsafe { libc::fcntl(p[1], libc::F_SETPIPE_SZ, CHUNK as libc::c_int) };
    Ok(Pipe(p))
}

/// Splice `src` into `dst` until EOF. Returns `Ok(None)` when splice is not
/// supported for these descriptors and nothing was transferred yet.
fn pump_splice(src: RawFd, dst: RawFd) -> io::Result<Option<u64>> {
    let pipe = new_pipe()?;
    let mut total = 0u64;
    loop {
        let n = unsafe {
            libc::splice(src, std::ptr::null_mut(), pipe.0[1], std::ptr::null_mut(), CHUNK, libc::SPLICE_F_MOVE)
        };
        if n < 0 {
            let e = last_err();
            match e.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::EINVAL) | Some(libc::ENOSYS) if total == 0 => return Ok(None),
                _ => return Err(e),
            }
        }
        if n == 0 {
            return Ok(Some(total));
        }
        let mut left = n as usize;
        while left > 0 {
            let m = unsafe {
                libc::splice(pipe.0[0], std::ptr::null_mut(), dst, std::ptr::null_mut(), left, libc::SPLICE_F_MOVE)
            };
            if m < 0 {
                let e = last_err();
                if e.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(e);
            }
            left -= m as usize;
        }
        total += n as u64;
    }
}

fn pump_copy(src: RawFd, dst: RawFd) -> io::Result<u64> {
    let mut buf = vec![0u8; FALLBACK_BUF];
    let mut total = 0u64;
    loop {
        let n = unsafe { libc::read(src, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            let e = last_err();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(e);
        }
        if n == 0 {
            return Ok(total);
        }
        let mut off = 0usize;
        while off < n as usize {
            let m = unsafe { libc::write(dst, buf[off..n as usize].as_ptr().cast(), n as usize - off) };
            if m < 0 {
                let e = last_err();
                if e.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(e);
            }
            off += m as usize;
        }
        total += n as u64;
    }
}

/// Copy everything from `src` to `dst` until EOF. `splice` selects the
/// zero-copy path when the descriptors support it.
pub fn pump(src: RawFd, dst: RawFd, splice: bool) -> io::Result<u64> {
    if splice
        && std::env::var_os("NETD_NO_SPLICE").is_none()
        && let Some(n) = pump_splice(src, dst)?
    {
        return Ok(n);
    }
    pump_copy(src, dst)
}

fn finish(src: RawFd, dst: RawFd, r: io::Result<u64>) {
    unsafe {
        match r {
            // Propagate EOF as a half-close so request/response protocols still work.
            Ok(_) => {
                libc::shutdown(dst, libc::SHUT_WR);
            }
            Err(_) => {
                libc::shutdown(src, libc::SHUT_RDWR);
                libc::shutdown(dst, libc::SHUT_RDWR);
            }
        }
    }
}

/// Relay bytes between `a` and `b` in both directions until both sides are
/// done. Blocks the calling thread; one extra thread is used.
pub fn relay(a: OwnedFd, b: OwnedFd) {
    relay_dirs(a, b, true, true);
}

/// Like [`relay`], choosing splice per direction. Splicing into a guest
/// AF_VSOCK socket makes the kernel emit multi-descriptor (non-linear) packets,
/// which some vhost-user-vsock backends cannot parse; such directions should
/// use plain writes.
pub fn relay_dirs(a: OwnedFd, b: OwnedFd, splice_ab: bool, splice_ba: bool) {
    let a = Arc::new(a);
    let b = Arc::new(b);
    let (a2, b2) = (a.clone(), b.clone());
    let t = thread::spawn(move || {
        let r = pump(a2.as_raw_fd(), b2.as_raw_fd(), splice_ab);
        finish(a2.as_raw_fd(), b2.as_raw_fd(), r);
    });
    let r = pump(b.as_raw_fd(), a.as_raw_fd(), splice_ba);
    finish(b.as_raw_fd(), a.as_raw_fd(), r);
    let _ = t.join();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    #[test]
    fn relays_both_directions_with_half_close() {
        let (mut left, a) = UnixStream::pair().unwrap();
        let (b, mut right) = UnixStream::pair().unwrap();
        let t = thread::spawn(move || relay(a.into(), b.into()));

        let payload: Vec<u8> = (0..3_000_000u32).map(|i| i as u8).collect();
        let p2 = payload.clone();
        let w = thread::spawn(move || {
            left.write_all(&p2).unwrap();
            left.shutdown(std::net::Shutdown::Write).unwrap();
            let mut back = Vec::new();
            left.read_to_end(&mut back).unwrap();
            back
        });
        let mut got = Vec::new();
        right.read_to_end(&mut got).unwrap();
        assert_eq!(got, payload);
        right.write_all(b"reply").unwrap();
        right.shutdown(std::net::Shutdown::Write).unwrap();
        assert_eq!(w.join().unwrap(), b"reply");
        t.join().unwrap();
    }
}
