//! Thread pool that serves a listening socket without per-connection setup.
//!
//! Every idle worker blocks in accept(), so the kernel wakes one of them and
//! that thread serves the connection itself: no hand-off between threads and
//! no thread creation on the connection's path. The pool grows when the
//! spare workers run low (long-lived connections keep their thread) and
//! shrinks again once enough are idle.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

/// Idle workers kept waiting in accept().
const SPARE: usize = 4;

struct Pool<C> {
    idle: AtomicUsize,
    accept: Box<dyn Fn() -> io::Result<C> + Send + Sync>,
    serve: Box<dyn Fn(C) + Send + Sync>,
}

/// Serves connections returned by `accept` with `serve`, from a pool of
/// threads; returns immediately.
pub fn spawn<C: 'static>(
    accept: impl Fn() -> io::Result<C> + Send + Sync + 'static,
    serve: impl Fn(C) + Send + Sync + 'static,
) {
    let p = Arc::new(Pool { idle: AtomicUsize::new(0), accept: Box::new(accept), serve: Box::new(serve) });
    for _ in 0..SPARE {
        start(&p);
    }
}

fn start<C: 'static>(p: &Arc<Pool<C>>) {
    let p = p.clone();
    p.idle.fetch_add(1, Ordering::SeqCst);
    thread::spawn(move || worker(&p));
}

fn worker<C: 'static>(p: &Arc<Pool<C>>) {
    loop {
        let r = (p.accept)();
        if p.idle.fetch_sub(1, Ordering::SeqCst) <= SPARE / 2 {
            start(p);
        }
        match r {
            Ok(c) => (p.serve)(c),
            Err(e) => eprintln!("netd-agent: accept: {e}"),
        }
        if p.idle.load(Ordering::SeqCst) >= SPARE {
            return;
        }
        p.idle.fetch_add(1, Ordering::SeqCst);
    }
}
