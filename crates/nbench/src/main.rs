//! nbench: latency and connection-rate microbenchmarks (complements iperf3).
//!
//!   nbench server ADDR                 serve rr / crr clients
//!   nbench rr ADDR [COUNT] [SIZE]      round-trip latency on one connection
//!   nbench crr ADDR [SECS]             connect + 1-byte request/response + close rate
//!
//! Clients print one JSON object.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::process::exit;
use std::thread;
use std::time::{Duration, Instant};

fn serve(addr: &str) {
    let l = TcpListener::bind(addr).unwrap_or_else(|e| {
        eprintln!("nbench: bind {addr}: {e}");
        exit(1)
    });
    for c in l.incoming().flatten() {
        thread::spawn(move || {
            let mut c = c;
            let _ = c.set_nodelay(true);
            let mut mode = [0u8; 5];
            if c.read_exact(&mut mode).is_err() {
                return;
            }
            let size = u32::from_be_bytes([mode[1], mode[2], mode[3], mode[4]]) as usize;
            match mode[0] {
                b'R' => {
                    let mut buf = vec![0u8; size.max(1)];
                    while c.read_exact(&mut buf).is_ok() {
                        if c.write_all(&buf).is_err() {
                            break;
                        }
                    }
                }
                b'C' => {
                    let _ = c.write_all(b"k");
                    // Server closes first so TIME_WAIT lands on the server port,
                    // not on the client's ephemeral ports.
                    let _ = c.shutdown(Shutdown::Both);
                }
                _ => {}
            }
        });
    }
}

fn connect(addr: &str) -> TcpStream {
    let c = TcpStream::connect(addr).unwrap_or_else(|e| {
        eprintln!("nbench: connect {addr}: {e}");
        exit(1)
    });
    c.set_nodelay(true).unwrap();
    c
}

fn rr(addr: &str, count: usize, size: usize) {
    let mut c = connect(addr);
    let mut hdr = vec![b'R'];
    hdr.extend_from_slice(&(size as u32).to_be_bytes());
    c.write_all(&hdr).unwrap();
    let msg = vec![7u8; size];
    let mut buf = vec![0u8; size];
    for _ in 0..count / 10 {
        c.write_all(&msg).unwrap();
        c.read_exact(&mut buf).unwrap();
    }
    let mut lat = Vec::with_capacity(count);
    for _ in 0..count {
        let t = Instant::now();
        c.write_all(&msg).unwrap();
        c.read_exact(&mut buf).unwrap();
        lat.push(t.elapsed().as_nanos() as f64 / 1000.0);
    }
    lat.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let avg = lat.iter().sum::<f64>() / lat.len() as f64;
    let p = |q: f64| lat[((lat.len() as f64 - 1.0) * q) as usize];
    println!(
        "{{\"count\":{count},\"size\":{size},\"avg_us\":{avg:.2},\"p50_us\":{:.2},\"p99_us\":{:.2},\"tps\":{:.0}}}",
        p(0.5),
        p(0.99),
        1e6 / avg
    );
}

fn crr(addr: &str, secs: u64) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    let start = Instant::now();
    let mut n = 0u64;
    let mut errors = 0u64;
    let mut b = [0u8; 1];
    while Instant::now() < deadline {
        let ok = (|| -> std::io::Result<()> {
            let mut c = TcpStream::connect(addr)?;
            c.set_nodelay(true)?;
            c.write_all(&[b'C', 0, 0, 0, 1])?;
            c.read_exact(&mut b)?;
            Ok(())
        })();
        match ok {
            Ok(()) => n += 1,
            Err(_) => errors += 1,
        }
    }
    let el = start.elapsed().as_secs_f64();
    println!("{{\"conns\":{n},\"errors\":{errors},\"secs\":{el:.2},\"conn_per_sec\":{:.0}}}", n as f64 / el);
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let arg = |i: usize, d: &str| a.get(i).cloned().unwrap_or_else(|| d.to_string());
    match a.get(1).map(String::as_str) {
        Some("server") => serve(&arg(2, "0.0.0.0:7000")),
        Some("rr") if a.len() > 2 => rr(&a[2], arg(3, "20000").parse().unwrap(), arg(4, "64").parse().unwrap()),
        Some("crr") if a.len() > 2 => crr(&a[2], arg(3, "5").parse().unwrap()),
        _ => {
            eprintln!("usage: nbench server ADDR | rr ADDR [COUNT] [SIZE] | crr ADDR [SECS]");
            exit(2)
        }
    }
}
