//! Receiving side of a vsock stream from netd (doorbells and frames).
//!
//! Since Linux 6.8 the guest's virtio-vsock sends the host a credit update
//! whenever a read leaves the receive queue empty. A doorbell is a single
//! byte, so reading it would cost a second packet (and VM exit) for every
//! doorbell. The inbox therefore leaves a trailing Bell byte unread: it peeks
//! at the queue and consumes everything but that byte, which is harmless to
//! hand over later. A queue that is never empty is always readable, so
//! waiting uses an edge-triggered epoll instance that fires on every arriving
//! packet instead.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use netd_common::proto::{Frame, FrameReader};

pub struct Inbox {
    fd: OwnedFd,
    ep: OwnedFd,
    frames: FrameReader,
    /// The queue starts with a Bell byte that was already handed over.
    held: bool,
}

impl Inbox {
    /// `fd` must be non-blocking.
    pub fn new(fd: OwnedFd) -> io::Result<Self> {
        let ep = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if ep < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: ep is a fresh descriptor owned by nobody else.
        let ep = unsafe { OwnedFd::from_raw_fd(ep) };
        let mut ev = libc::epoll_event { events: (libc::EPOLLIN | libc::EPOLLRDHUP | libc::EPOLLET) as u32, u64: 0 };
        if unsafe { libc::epoll_ctl(ep.as_raw_fd(), libc::EPOLL_CTL_ADD, fd.as_raw_fd(), &mut ev) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Inbox { fd, ep, frames: FrameReader::default(), held: false })
    }

    /// The stream, for sending.
    pub fn fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Readable (for poll) when frames may have arrived since the last read().
    pub fn wait_fd(&self) -> RawFd {
        self.ep.as_raw_fd()
    }

    /// Hands every frame that arrived to `f` and returns its first error.
    /// EOF (netd went away) is ConnectionReset.
    pub fn read(&mut self, mut f: impl FnMut(Frame) -> io::Result<()>) -> io::Result<()> {
        let mut ev = libc::epoll_event { events: 0, u64: 0 };
        if unsafe { libc::epoll_wait(self.ep.as_raw_fd(), &mut ev, 1, 0) } <= 0 {
            return Ok(());
        }
        let hup = ev.events & (libc::EPOLLRDHUP | libc::EPOLLHUP) as u32 != 0;
        let mut first_err = None;
        let mut feed = |frames: &mut FrameReader, b: &[u8]| {
            let r = frames.feed(b, |fr| {
                if first_err.is_none() {
                    first_err = f(fr).err();
                }
                Ok(())
            });
            if let Err(e) = r {
                first_err.get_or_insert(e);
            }
        };
        let mut b = [0u8; 256];
        loop {
            let n = unsafe { libc::recv(self.fd(), b.as_mut_ptr().cast(), b.len(), libc::MSG_PEEK | libc::MSG_DONTWAIT) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::Interrupted {
                    break;
                }
                return Err(e);
            }
            let n = n as usize;
            if n == 0 {
                return Err(io::ErrorKind::ConnectionReset.into());
            }
            let new = &b[self.held as usize..n];
            let keep = match new.split_last() {
                // Nothing new; EOF only shows once the queue is empty.
                None if !hup => break,
                None => false,
                Some((&last, rest)) => {
                    feed(&mut self.frames, rest);
                    let keep = n < b.len() && last == 0 && self.frames.at_boundary();
                    if !keep {
                        feed(&mut self.frames, &[last]);
                    }
                    keep
                }
            };
            let take = n - keep as usize;
            if unsafe { libc::recv(self.fd(), b.as_mut_ptr().cast(), take, libc::MSG_DONTWAIT) } != take as isize {
                return Err(io::Error::other("vsock stream lost peeked bytes"));
            }
            self.held = keep;
            if keep {
                break;
            }
        }
        first_err.map_or(Ok(()), Err)
    }
}
