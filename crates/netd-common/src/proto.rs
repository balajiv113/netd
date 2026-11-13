//! Offload wire protocol.
//!
//! The guest agent opens one stream (vsock) per offloaded guest connection
//! and sends a request:
//!
//! ```text
//! 'N' 'D' version proto family port(be16) addr(4 or 16 bytes) slot(be16)
//! ```
//!
//! The answer is a 6-byte status: errno (be i32, 0 = connected) and the
//! shared-memory slot that carries the payload (`NO_SLOT`: the stream itself
//! carries raw payload bytes). Host port forwards use the same request in the
//! other direction; there the guest picks the slot and returns it.
//!
//! Once per boot the agent may register its shared rings (see [`crate::shm`])
//! on a stream of its own, which stays open for the registration's lifetime:
//!
//! ```text
//! 'N' 'D' version PROTO_SHM nslots(be16) ctl_gpa(be64) ring_gpa(be64) * 2 * nslots
//! ```
//!
//! It then opens one *slot stream* per slot, answered with a status:
//!
//! ```text
//! 'N' 'D' version PROTO_SLOT slot(be16)
//! ```
//!
//! A slot stream carries the slot's outbound connections one after another,
//! so a new connection costs no vsock setup or teardown. It only carries
//! [`Frame`]s: the payload is in the slot's rings.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::shm::{MAX_SLOTS, NO_SLOT};

pub const MAGIC: [u8; 2] = *b"ND";
pub const VERSION: u8 = 3;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_SHM: u8 = 0xfe;
pub const PROTO_SLOT: u8 = 0xfd;
pub const STATUS_LEN: usize = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request {
    pub proto: u8,
    pub dst: SocketAddr,
    pub slot: u16,
}

/// Guest-physical addresses of the agent's shared rings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShmRegion {
    pub ctl_gpa: u64,
    /// g2h and h2g ring of every slot, in slot order.
    pub ring_gpas: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Msg {
    Connect(Request),
    Shm(ShmRegion),
    /// Binds the stream to a slot (see [`Frame`]).
    Slot(u16),
}

const F_BELL: u8 = 0;
const F_OPEN: u8 = b'O';
const F_CLOSE: u8 = b'C';
const F_RESET: u8 = b'R';
const F_FAIL: u8 = b'F';

/// A message on a slot stream.
///
/// The agent starts a connection with `Open` and ends it with exactly one
/// `Close` (it is done with both directions; netd flushes what is left in
/// the ring) or `Reset`. netd answers only on failure: `Fail` ends the
/// connection `id` on netd's side (a failed connect, or the host socket
/// broke); a `Close` or `Reset` for it may still follow and is ignored.
/// Either side sends `Bell` when the other one asked to be woken (see
/// [`crate::shm`]). netd frees the slot (`SlotCtl::release`) once the
/// connection has ended on its side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frame {
    Bell,
    Open { id: u32, dst: SocketAddr },
    Close,
    Reset,
    Fail { id: u32, errno: i32 },
}

fn bad(m: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, m.to_string())
}

/// family port(be16) addr(4 or 16 bytes)
fn encode_addr(a: SocketAddr, b: &mut Vec<u8>) {
    match a.ip() {
        IpAddr::V4(ip) => {
            b.push(4);
            b.extend_from_slice(&a.port().to_be_bytes());
            b.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            b.push(6);
            b.extend_from_slice(&a.port().to_be_bytes());
            b.extend_from_slice(&ip.octets());
        }
    }
}

/// Length of an encoded address as far as its first byte tells.
fn addr_len(family: Option<&u8>) -> usize {
    match family {
        None => 1,
        Some(6) => 3 + 16,
        Some(_) => 3 + 4,
    }
}

fn parse_addr(b: &[u8]) -> io::Result<SocketAddr> {
    let port = u16::from_be_bytes([b[1], b[2]]);
    let ip = match b[0] {
        4 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&b[3..7]).unwrap())),
        6 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&b[3..19]).unwrap())),
        _ => return Err(bad("bad address family")),
    };
    Ok(SocketAddr::new(ip, port))
}

impl Request {
    pub fn tcp(dst: SocketAddr, slot: u16) -> Self {
        Self { proto: PROTO_TCP, dst, slot }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(25);
        b.extend_from_slice(&MAGIC);
        b.push(VERSION);
        b.push(self.proto);
        encode_addr(self.dst, &mut b);
        b.extend_from_slice(&self.slot.to_be_bytes());
        b
    }
}

pub fn encode_slot(slot: u16) -> [u8; 6] {
    let s = slot.to_be_bytes();
    [MAGIC[0], MAGIC[1], VERSION, PROTO_SLOT, s[0], s[1]]
}

impl Frame {
    /// Total frame length as far as the prefix `b` (at least one byte) tells.
    pub fn need(b: &[u8]) -> usize {
        match b[0] {
            F_OPEN => 5 + addr_len(b.get(5)),
            F_FAIL => 9,
            _ => 1,
        }
    }

    /// Parses a complete frame (`b.len() == need(b)`).
    pub fn parse(b: &[u8]) -> io::Result<Self> {
        let be32 = |o: usize| u32::from_be_bytes(b[o..o + 4].try_into().unwrap());
        Ok(match b[0] {
            F_BELL => Frame::Bell,
            F_OPEN => Frame::Open { id: be32(1), dst: parse_addr(&b[5..])? },
            F_CLOSE => Frame::Close,
            F_RESET => Frame::Reset,
            F_FAIL => Frame::Fail { id: be32(1), errno: be32(5) as i32 },
            _ => return Err(bad("bad slot frame")),
        })
    }

    pub fn encode(&self, b: &mut Vec<u8>) {
        match *self {
            Frame::Bell => b.push(F_BELL),
            Frame::Open { id, dst } => {
                b.push(F_OPEN);
                b.extend_from_slice(&id.to_be_bytes());
                encode_addr(dst, b);
            }
            Frame::Close => b.push(F_CLOSE),
            Frame::Reset => b.push(F_RESET),
            Frame::Fail { id, errno } => {
                b.push(F_FAIL);
                b.extend_from_slice(&id.to_be_bytes());
                b.extend_from_slice(&errno.to_be_bytes());
            }
        }
    }
}

/// Reassembles frames from a byte stream.
#[derive(Default)]
pub struct FrameReader {
    part: Vec<u8>,
}

impl FrameReader {
    /// No partial frame is buffered.
    pub fn at_boundary(&self) -> bool {
        self.part.is_empty()
    }

    /// Feeds `b`, calling `f` for every complete frame.
    pub fn feed(&mut self, mut b: &[u8], mut f: impl FnMut(Frame) -> io::Result<()>) -> io::Result<()> {
        while !b.is_empty() {
            if self.part.is_empty() && b[0] == F_BELL {
                f(Frame::Bell)?;
                b = &b[1..];
                continue;
            }
            loop {
                let need = if self.part.is_empty() { 1 } else { Frame::need(&self.part) };
                if self.part.len() == need || b.is_empty() {
                    break;
                }
                let take = (need - self.part.len()).min(b.len());
                self.part.extend_from_slice(&b[..take]);
                b = &b[take..];
            }
            if self.part.len() == Frame::need(&self.part) {
                let fr = Frame::parse(&self.part);
                self.part.clear();
                f(fr?)?;
            }
        }
        Ok(())
    }
}

impl ShmRegion {
    pub fn slots(&self) -> usize {
        self.ring_gpas.len() / 2
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(14 + 8 * self.ring_gpas.len());
        b.extend_from_slice(&MAGIC);
        b.push(VERSION);
        b.push(PROTO_SHM);
        b.extend_from_slice(&(self.slots() as u16).to_be_bytes());
        b.extend_from_slice(&self.ctl_gpa.to_be_bytes());
        for g in &self.ring_gpas {
            b.extend_from_slice(&g.to_be_bytes());
        }
        b
    }
}

impl Msg {
    /// Total message length as far as the prefix `b` tells; the message is
    /// complete once `b.len() >= need(b)`.
    pub fn need(b: &[u8]) -> usize {
        if b.len() < 4 {
            return 4;
        }
        match b[3] {
            PROTO_SLOT => 6,
            PROTO_SHM if b.len() < 6 => 6,
            PROTO_SHM => 14 + 16 * (u16::from_be_bytes([b[4], b[5]]) as usize).min(MAX_SLOTS),
            _ => 4 + addr_len(b.get(4)) + 2,
        }
    }

    pub fn parse(b: &[u8]) -> io::Result<Self> {
        if b.len() < 4 || b[..2] != MAGIC || b[2] != VERSION {
            return Err(bad("bad offload header"));
        }
        if b.len() < Self::need(b) {
            return Err(bad("short offload header"));
        }
        let be64 = |o: usize| u64::from_be_bytes(b[o..o + 8].try_into().unwrap());
        match b[3] {
            PROTO_SLOT => Ok(Msg::Slot(u16::from_be_bytes([b[4], b[5]]))),
            PROTO_SHM => {
                let n = u16::from_be_bytes([b[4], b[5]]) as usize;
                if n == 0 || n > MAX_SLOTS {
                    return Err(bad("bad slot count"));
                }
                let ring_gpas = (0..2 * n).map(|i| be64(14 + 8 * i)).collect();
                Ok(Msg::Shm(ShmRegion { ctl_gpa: be64(6), ring_gpas }))
            }
            proto => {
                let at = 4 + addr_len(b.get(4));
                let slot = u16::from_be_bytes([b[at], b[at + 1]]);
                Ok(Msg::Connect(Request { proto, dst: parse_addr(&b[4..at])?, slot }))
            }
        }
    }

    pub fn read_from(r: &mut impl Read) -> io::Result<Self> {
        let mut b = Vec::with_capacity(32);
        while b.len() < Self::need(&b) {
            let at = b.len();
            b.resize(Self::need(&b), 0);
            r.read_exact(&mut b[at..])?;
        }
        Self::parse(&b)
    }
}

pub fn encode_status(errno: i32, slot: u16) -> [u8; STATUS_LEN] {
    let mut b = [0u8; STATUS_LEN];
    b[..4].copy_from_slice(&errno.to_be_bytes());
    b[4..].copy_from_slice(&slot.to_be_bytes());
    b
}

pub fn parse_status(b: &[u8; STATUS_LEN]) -> (i32, u16) {
    (i32::from_be_bytes(b[..4].try_into().unwrap()), u16::from_be_bytes([b[4], b[5]]))
}

pub fn write_status(w: &mut impl Write, errno: i32, slot: u16) -> io::Result<()> {
    w.write_all(&encode_status(errno, slot))
}

/// Status for a failed request.
pub fn write_error(w: &mut impl Write, errno: i32) -> io::Result<()> {
    write_status(w, errno, NO_SLOT)
}

/// Reads a status; returns the errno and the slot (`NO_SLOT` if none).
pub fn read_status(r: &mut impl Read) -> io::Result<(i32, u16)> {
    let mut b = [0u8; STATUS_LEN];
    r.read_exact(&mut b)?;
    Ok(parse_status(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_v4_v6() {
        for dst in ["192.168.5.2:5201", "[fd00:5::2]:443"] {
            let req = Request::tcp(dst.parse().unwrap(), 3);
            let got = Msg::read_from(&mut req.encode().as_slice()).unwrap();
            assert_eq!(got, Msg::Connect(req));
        }
    }

    #[test]
    fn roundtrip_shm() {
        let r = ShmRegion { ctl_gpa: 0x4000_0000, ring_gpas: vec![1 << 21, 2 << 21, 3 << 21, 4 << 21] };
        let b = r.encode();
        assert_eq!(Msg::need(&b), b.len());
        assert_eq!(Msg::read_from(&mut b.as_slice()).unwrap(), Msg::Shm(r));
    }

    #[test]
    fn rejects_bad_input() {
        let mut b = Request::tcp("1.2.3.4:5".parse().unwrap(), NO_SLOT).encode();
        b[0] = b'X';
        assert!(Msg::read_from(&mut b.as_slice()).is_err());
        let mut s = ShmRegion { ctl_gpa: 0, ring_gpas: vec![0, 0] }.encode();
        s[4..6].copy_from_slice(&0u16.to_be_bytes());
        assert!(Msg::parse(&s).is_err());
    }

    #[test]
    fn roundtrip_slot() {
        let b = encode_slot(9);
        assert_eq!(Msg::need(&b), b.len());
        assert_eq!(Msg::read_from(&mut b.as_slice()).unwrap(), Msg::Slot(9));
    }

    #[test]
    fn frames_reassemble_across_reads() {
        let frames = [
            Frame::Bell,
            Frame::Open { id: 7, dst: "192.168.5.2:80".parse().unwrap() },
            Frame::Bell,
            Frame::Open { id: u32::MAX, dst: "[fd00:5::2]:443".parse().unwrap() },
            Frame::Fail { id: 7, errno: 111 },
            Frame::Close,
            Frame::Reset,
        ];
        let mut b = Vec::new();
        for f in &frames {
            f.encode(&mut b);
        }
        for step in [1, 2, 3, 5, b.len()] {
            let (mut r, mut got) = (FrameReader::default(), Vec::new());
            for c in b.chunks(step) {
                r.feed(c, |f| {
                    got.push(f);
                    Ok(())
                })
                .unwrap();
            }
            assert_eq!(got, frames, "chunks of {step}");
        }
        assert!(FrameReader::default().feed(b"X", |_| Ok(())).is_err());
    }

    #[test]
    fn status_roundtrip() {
        let mut b = Vec::new();
        write_status(&mut b, 111, 7).unwrap();
        assert_eq!(read_status(&mut b.as_slice()).unwrap(), (111, 7));
    }
}
