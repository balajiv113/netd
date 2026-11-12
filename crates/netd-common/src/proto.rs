//! Offload wire protocol.
//!
//! The guest agent opens one stream (vsock) per offloaded guest connection
//! and sends a request header:
//!
//! ```text
//! 'N' 'D' version proto family port(be16) addr(4 or 16 bytes)
//! ```
//!
//! netd answers with a big-endian i32 status (0 = connected, otherwise an
//! errno value) and from then on the stream carries raw payload bytes.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const MAGIC: [u8; 2] = *b"ND";
pub const VERSION: u8 = 1;
pub const PROTO_TCP: u8 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request {
    pub proto: u8,
    pub dst: SocketAddr,
}

impl Request {
    pub fn tcp(dst: SocketAddr) -> Self {
        Self { proto: PROTO_TCP, dst }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(23);
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
        b
    }

    pub fn read_from(r: &mut impl Read) -> io::Result<Self> {
        let mut h = [0u8; 7];
        r.read_exact(&mut h)?;
        if h[..2] != MAGIC || h[2] != VERSION {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad offload header"));
        }
        let port = u16::from_be_bytes([h[5], h[6]]);
        let ip = match h[4] {
            4 => {
                let mut a = [0u8; 4];
                r.read_exact(&mut a)?;
                IpAddr::V4(Ipv4Addr::from(a))
            }
            6 => {
                let mut a = [0u8; 16];
                r.read_exact(&mut a)?;
                IpAddr::V6(Ipv6Addr::from(a))
            }
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "bad address family")),
        };
        Ok(Self { proto: h[3], dst: SocketAddr::new(ip, port) })
    }
}

pub fn write_status(w: &mut impl Write, errno: i32) -> io::Result<()> {
    w.write_all(&errno.to_be_bytes())
}

pub fn read_status(r: &mut impl Read) -> io::Result<i32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(i32::from_be_bytes(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_v4_v6() {
        for dst in ["192.168.5.2:5201", "[fd00:5::2]:443"] {
            let req = Request::tcp(dst.parse().unwrap());
            let got = Request::read_from(&mut req.encode().as_slice()).unwrap();
            assert_eq!(got, req);
        }
    }

    #[test]
    fn rejects_bad_magic() {
        let mut b = Request::tcp("1.2.3.4:5".parse().unwrap()).encode();
        b[0] = b'X';
        assert!(Request::read_from(&mut b.as_slice()).is_err());
    }
}
