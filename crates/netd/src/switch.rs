//! Experimental Ethernet switching over QEMU's length-prefixed socket backend.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const MAX_PORTS: usize = 64;
const MAX_FRAME: usize = 65_536;
const QUEUE_FRAMES: usize = 1024;
const QUEUE_BYTES: usize = 4 * 1024 * 1024;
const MAX_MACS: usize = 4096;
const MAC_AGE: Duration = Duration::from_secs(300);

type Frame = Arc<[u8]>;
type Mac = [u8; 6];
type MacKey = (Mac, [u16; 2], u8);

struct Learned {
    port: u64,
    seen: Instant,
}

struct Port {
    tx: SyncSender<Frame>,
    queued: Arc<AtomicUsize>,
}

#[derive(Default)]
struct Switch {
    next_port: u64,
    ports: HashMap<u64, Port>,
    macs: HashMap<MacKey, Learned>,
    dropped: u64,
}

impl Switch {
    fn attach(&mut self, tx: SyncSender<Frame>) -> io::Result<(u64, Arc<AtomicUsize>)> {
        if self.ports.len() == MAX_PORTS {
            return Err(io::Error::other("switch port limit reached"));
        }
        let id = self.next_port;
        self.next_port = self.next_port.checked_add(1).ok_or_else(|| io::Error::other("switch port IDs exhausted"))?;
        let queued = Arc::new(AtomicUsize::new(0));
        self.ports.insert(id, Port { tx, queued: queued.clone() });
        Ok((id, queued))
    }

    fn detach(&mut self, port: u64) {
        self.ports.remove(&port);
        self.macs.retain(|_, entry| entry.port != port);
    }

    fn forward(&mut self, port: u64, frame: Frame) {
        if !self.ports.contains_key(&port) {
            return;
        }
        let dst: Mac = frame[4..10].try_into().unwrap();
        let src: Mac = frame[10..16].try_into().unwrap();
        let now = Instant::now();
        let vlan = vlan_key(&frame[4..]);
        if let Some((tags, count)) = vlan && src[0] & 1 == 0 && src != [0; 6] {
            let key = (src, tags, count);
            if !self.macs.contains_key(&key) && self.macs.len() == MAX_MACS
                && let Some(oldest) = self.macs.iter().min_by_key(|(_, entry)| entry.seen).map(|(&mac, _)| mac)
            {
                self.macs.remove(&oldest);
            }
            self.macs.insert(key, Learned { port, seen: now });
        }

        let target = if dst[0] & 1 == 0 {
            vlan.and_then(|(tags, count)| self.macs.get(&(dst, tags, count)))
                .filter(|entry| now.duration_since(entry.seen) < MAC_AGE).map(|entry| entry.port)
        } else {
            None
        };
        for (&id, target_port) in &self.ports {
            if id == port || target.is_some_and(|target| target != id) {
                continue;
            }
            let previous = target_port.queued.fetch_add(frame.len(), Ordering::Relaxed);
            let reserved = previous + frame.len() <= QUEUE_BYTES;
            let full = if reserved {
                match target_port.tx.try_send(frame.clone()) {
                    Ok(()) => false,
                    Err(e) => {
                        target_port.queued.fetch_sub(frame.len(), Ordering::Relaxed);
                        matches!(e, TrySendError::Full(_))
                    }
                }
            } else {
                target_port.queued.fetch_sub(frame.len(), Ordering::Relaxed);
                true
            };
            if full {
                self.dropped += 1;
                if self.dropped.is_power_of_two() {
                    eprintln!("netd: switch: {} frames dropped due to full port queues", self.dropped);
                }
            }
        }
    }
}

fn vlan_key(frame: &[u8]) -> Option<([u16; 2], u8)> {
    let mut tags = [0; 2];
    let mut count = 0usize;
    let mut off = 12;
    loop {
        let ethertype = u16::from_be_bytes(frame.get(off..off + 2)?.try_into().ok()?);
        if !matches!(ethertype, 0x8100 | 0x88a8 | 0x9100) {
            return Some((tags, count as u8));
        }
        if count == tags.len() {
            return None;
        }
        tags[count] = u16::from_be_bytes(frame.get(off + 2..off + 4)?.try_into().ok()?) & 0x0fff;
        count += 1;
        off += 4;
    }
}

fn read_frame(stream: &mut TcpStream) -> io::Result<Option<Frame>> {
    let mut prefix = [0; 4];
    loop {
        match stream.read(&mut prefix[..1]) {
            Ok(0) => return Ok(None),
            Ok(1) => break,
            Ok(_) => unreachable!(),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    stream.read_exact(&mut prefix[1..])?;
    let len = u32::from_be_bytes(prefix) as usize;
    if !(14..=MAX_FRAME).contains(&len) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("invalid Ethernet frame length {len}")));
    }
    let mut frame = vec![0; len + 4];
    frame[..4].copy_from_slice(&prefix);
    stream.read_exact(&mut frame[4..])?;
    Ok(Some(frame.into()))
}

fn attach(stream: TcpStream, switch: Arc<Mutex<Switch>>) -> io::Result<()> {
    stream.set_nodelay(true)?;
    let mut reader = stream.try_clone()?;
    let mut writer = stream;
    let (tx, rx) = mpsc::sync_channel::<Frame>(QUEUE_FRAMES);
    let (port, queued) = switch.lock().unwrap().attach(tx)?;
    let sw = switch.clone();
    if let Err(e) = thread::Builder::new().name(format!("netd-switch-tx-{port}")).spawn(move || {
        for frame in rx {
            let result = writer.write_all(&frame);
            queued.fetch_sub(frame.len(), Ordering::Relaxed);
            if let Err(e) = result {
                eprintln!("netd: switch: port {port} write: {e}");
                break;
            }
        }
        let _ = writer.shutdown(Shutdown::Both);
        sw.lock().unwrap().detach(port);
    }) {
        switch.lock().unwrap().detach(port);
        return Err(e);
    }
    let sw = switch.clone();
    if let Err(e) = thread::Builder::new().name(format!("netd-switch-rx-{port}")).spawn(move || {
        loop {
            match read_frame(&mut reader) {
                Ok(Some(frame)) => sw.lock().unwrap().forward(port, frame),
                Ok(None) => break,
                Err(e) => {
                    eprintln!("netd: switch: port {port} read: {e}");
                    break;
                }
            }
        }
        sw.lock().unwrap().detach(port);
        let _ = reader.shutdown(Shutdown::Both);
    }) {
        switch.lock().unwrap().detach(port);
        return Err(e);
    }
    Ok(())
}

pub fn run(mut args: impl Iterator<Item = String>) -> io::Result<()> {
    let usage = "usage: netd switch --listen 127.0.0.1:PORT";
    let flag = args.next().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, usage))?;
    if flag == "--help" && args.next().is_none() {
        println!("{usage}");
        return Ok(());
    }
    if flag != "--listen" {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, usage));
    }
    let addr: SocketAddr = args.next().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, usage))?
        .parse().map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    if args.next().is_some() || !addr.ip().is_loopback() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "switch requires a loopback listen address"));
    }
    let listener = TcpListener::bind(addr)?;
    eprintln!("netd: experimental Ethernet switch listening on {}", listener.local_addr()?);
    let switch = Arc::new(Mutex::new(Switch::default()));
    for stream in listener.incoming() {
        let stream = stream?;
        if let Err(e) = attach(stream, switch.clone()) {
            eprintln!("netd: switch: cannot attach port: {e}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(dst: Mac, src: Mac) -> Frame {
        let mut bytes = vec![0; 18];
        bytes[..4].copy_from_slice(&14u32.to_be_bytes());
        bytes[4..10].copy_from_slice(&dst);
        bytes[10..16].copy_from_slice(&src);
        bytes.into()
    }

    fn tagged(dst: Mac, src: Mac, vlan: u16) -> Frame {
        let mut bytes = vec![0; 22];
        bytes[..4].copy_from_slice(&18u32.to_be_bytes());
        bytes[4..10].copy_from_slice(&dst);
        bytes[10..16].copy_from_slice(&src);
        bytes[16..18].copy_from_slice(&0x8100u16.to_be_bytes());
        bytes[18..20].copy_from_slice(&vlan.to_be_bytes());
        bytes.into()
    }

    #[test]
    fn learns_unicast_floods_broadcast_and_forgets_disconnected_port() {
        let mut sw = Switch::default();
        let (a, arx) = mpsc::sync_channel(4);
        let (b, brx) = mpsc::sync_channel(4);
        let (c, crx) = mpsc::sync_channel(4);
        let a = sw.attach(a).unwrap().0;
        let b = sw.attach(b).unwrap().0;
        let c = sw.attach(c).unwrap().0;
        let am = [2, 0, 0, 0, 0, 1];
        let bm = [2, 0, 0, 0, 0, 2];
        sw.forward(a, frame([255; 6], am));
        assert!(arx.try_recv().is_err());
        assert!(brx.try_recv().is_ok());
        assert!(crx.try_recv().is_ok());
        sw.forward(b, frame(am, bm));
        assert!(arx.try_recv().is_ok());
        assert!(crx.try_recv().is_err());
        sw.detach(a);
        sw.forward(a, frame([255; 6], am));
        assert!(brx.try_recv().is_err());
        assert!(crx.try_recv().is_err());
        sw.forward(b, frame(am, bm));
        assert!(crx.try_recv().is_ok());
        assert!(sw.ports.contains_key(&c));
    }

    #[test]
    fn bounded_queues_do_not_block_other_ports() {
        let mut sw = Switch::default();
        let (a, _) = mpsc::sync_channel(1);
        let (b, brx) = mpsc::sync_channel(1);
        let (c, crx) = mpsc::sync_channel(2);
        let a = sw.attach(a).unwrap().0;
        sw.attach(b).unwrap();
        sw.attach(c).unwrap();
        let f = frame([255; 6], [2, 0, 0, 0, 0, 1]);
        sw.forward(a, f.clone());
        sw.forward(a, f);
        assert_eq!(sw.dropped, 1);
        assert!(brx.try_recv().is_ok());
        assert!(crx.try_recv().is_ok());
        assert!(crx.try_recv().is_ok());
    }

    #[test]
    fn queue_bytes_are_bounded_even_for_large_frames() {
        let mut sw = Switch::default();
        let (a, _) = mpsc::sync_channel(1);
        let (b, _rx) = mpsc::sync_channel(QUEUE_FRAMES);
        let a = sw.attach(a).unwrap().0;
        let (_, queued) = sw.attach(b).unwrap();
        let mut bytes = vec![0; MAX_FRAME + 4];
        bytes[..4].copy_from_slice(&(MAX_FRAME as u32).to_be_bytes());
        bytes[4..10].copy_from_slice(&[255; 6]);
        bytes[10..16].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
        let f: Frame = bytes.into();
        for _ in 0..100 {
            sw.forward(a, f.clone());
        }
        assert!(sw.dropped > 0);
        assert!(queued.load(Ordering::Relaxed) <= QUEUE_BYTES);
    }

    #[test]
    fn learns_addresses_separately_for_each_vlan() {
        let mut sw = Switch::default();
        let (a, arx) = mpsc::sync_channel(4);
        let (b, brx) = mpsc::sync_channel(4);
        let (c, crx) = mpsc::sync_channel(4);
        let a = sw.attach(a).unwrap().0;
        let b = sw.attach(b).unwrap().0;
        let c = sw.attach(c).unwrap().0;
        let same = [2, 0, 0, 0, 0, 1];
        sw.forward(a, tagged([255; 6], same, 1));
        brx.try_recv().unwrap();
        crx.try_recv().unwrap();
        sw.forward(b, tagged([255; 6], same, 2));
        arx.try_recv().unwrap();
        crx.try_recv().unwrap();
        sw.forward(c, tagged(same, [2, 0, 0, 0, 0, 3], 1));
        assert!(arx.try_recv().is_ok());
        assert!(brx.try_recv().is_err());
        sw.forward(c, tagged(same, [2, 0, 0, 0, 0, 3], 2));
        assert!(brx.try_recv().is_ok());
        assert!(arx.try_recv().is_err());
    }

    #[test]
    fn socket_ports_forward_fragmented_frames_and_reject_invalid_lengths() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut a = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server_a, _) = listener.accept().unwrap();
        let mut b = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server_b, _) = listener.accept().unwrap();
        a.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        b.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let switch = Arc::new(Mutex::new(Switch::default()));
        attach(server_a, switch.clone()).unwrap();
        attach(server_b, switch).unwrap();
        let f = frame([255; 6], [2, 0, 0, 0, 0, 1]);
        a.write_all(&f[..2]).unwrap();
        a.write_all(&f[2..]).unwrap();
        assert_eq!(&*read_frame(&mut b).unwrap().unwrap(), &*f);
        a.write_all(&u32::MAX.to_be_bytes()).unwrap();
        match read_frame(&mut a) {
            Ok(None) => {}
            Err(e) if matches!(e.kind(), io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted) => {}
            other => panic!("expected closed port, got {other:?}"),
        }
    }
}
