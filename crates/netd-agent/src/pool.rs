//! Pre-connected upstream connections.
//!
//! Opening a vsock stream costs a round trip to the host. Outbound
//! connections take an already-open stream from the pool instead, so a new
//! guest connection only waits for netd's reply to its request. A background
//! thread refills the pool.

use std::io;
use std::os::fd::OwnedFd;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

/// Delay before retrying after the pool failed to open a stream.
const RETRY: Duration = Duration::from_millis(100);

type Connect = Box<dyn Fn() -> io::Result<OwnedFd> + Send + Sync>;

pub struct Pool {
    idle: Mutex<Vec<OwnedFd>>,
    low: Condvar,
    size: usize,
    connect: Connect,
}

/// Where a stream came from. A pooled stream may have been reset while idle
/// (e.g. netd restarted), so callers retry those once on a fresh stream.
pub enum Origin {
    Pooled,
    Fresh,
}

impl Pool {
    /// Keeps `size` streams open; `size == 0` connects on demand only.
    pub fn new(size: usize, connect: Connect) -> Arc<Self> {
        let p = Arc::new(Pool { idle: Mutex::new(Vec::with_capacity(size)), low: Condvar::new(), size, connect });
        if size > 0 {
            let q = p.clone();
            thread::spawn(move || q.refill());
        }
        p
    }

    pub fn take(&self) -> io::Result<(OwnedFd, Origin)> {
        if let Some(fd) = self.idle.lock().unwrap().pop() {
            self.low.notify_one();
            return Ok((fd, Origin::Pooled));
        }
        Ok(((self.connect)()?, Origin::Fresh))
    }

    pub fn fresh(&self) -> io::Result<OwnedFd> {
        (self.connect)()
    }

    fn refill(&self) {
        loop {
            {
                let mut idle = self.idle.lock().unwrap();
                while idle.len() >= self.size {
                    idle = self.low.wait(idle).unwrap();
                }
            }
            match (self.connect)() {
                Ok(fd) => self.idle.lock().unwrap().push(fd),
                Err(_) => thread::sleep(RETRY),
            }
        }
    }
}
