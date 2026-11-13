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

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::shm::{MAX_SLOTS, NO_SLOT};

pub const MAGIC: [u8; 2] = *b"ND";
pub const VERSION: u8 = 2;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_SHM: u8 = 0xfe;
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
}

fn bad(m: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, m.to_string())
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
        match self.dst.ip() {
            IpAddr::V4(ip) => {
                b.push(4);
                b.extend_from_slice(&self.dst.port().to_be_bytes());
                b.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                b.push(6);
                b.extend_from_slice(&self.dst.port().to_be_bytes());
                b.extend_from_slice(&ip.octets());
            }
        }
        b.extend_from_slice(&self.slot.to_be_bytes());
        b
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
        match (b.get(3), b.get(4)) {
            (Some(&PROTO_SHM), _) if b.len() >= 6 => {
                let n = u16::from_be_bytes([b[4], b[5]]) as usize;
                14 + 16 * n.min(MAX_SLOTS)
            }
            (_, Some(6)) if b[3] != PROTO_SHM => 7 + 16 + 2,
            (_, Some(_)) if b[3] != PROTO_SHM => 7 + 4 + 2,
            _ => 7,
        }
    }

    pub fn parse(b: &[u8]) -> io::Result<Self> {
        if b.len() < 7 || b[..2] != MAGIC || b[2] != VERSION {
            return Err(bad("bad offload header"));
        }
        if b.len() < Self::need(b) {
            return Err(bad("short offload header"));
        }
        let be64 = |o: usize| u64::from_be_bytes(b[o..o + 8].try_into().unwrap());
        if b[3] == PROTO_SHM {
            let n = u16::from_be_bytes([b[4], b[5]]) as usize;
            if n == 0 || n > MAX_SLOTS {
                return Err(bad("bad slot count"));
            }
            let ring_gpas = (0..2 * n).map(|i| be64(14 + 8 * i)).collect();
            return Ok(Msg::Shm(ShmRegion { ctl_gpa: be64(6), ring_gpas }));
        }
        let port = u16::from_be_bytes([b[5], b[6]]);
        let (ip, at) = match b[4] {
            4 => (IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&b[7..11]).unwrap())), 11),
            6 => (IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&b[7..23]).unwrap())), 23),
            _ => return Err(bad("bad address family")),
        };
        let slot = u16::from_be_bytes([b[at], b[at + 1]]);
        Ok(Msg::Connect(Request { proto: b[3], dst: SocketAddr::new(ip, port), slot }))
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
    fn status_roundtrip() {
        let mut b = Vec::new();
        write_status(&mut b, 111, 7).unwrap();
        assert_eq!(read_status(&mut b.as_slice()).unwrap(), (111, 7));
    }
}
