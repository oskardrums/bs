use cvt::cvt;
use libc::{
    close, socket, AF_INET, AF_INET6, AF_PACKET, AF_UNIX, IPPROTO_SCTP, IPPROTO_TCP, IPPROTO_UDP,
    IPPROTO_UDPLITE, SOCK_DGRAM, SOCK_RAW, SOCK_SEQPACKET, SOCK_STREAM,
};
#[cfg(target_os = "linux")]
use libc::{SOCK_CLOEXEC, SOCK_NONBLOCK};
use std::io::ErrorKind::Interrupted;
use std::io::Result;

#[derive(PartialEq, Eq, Clone)]
pub enum Domain {
    Unix = AF_UNIX as isize,
    Inet = AF_INET as isize,
    Inet6 = AF_INET6 as isize,
    Packet = AF_PACKET as isize,
}

#[derive(PartialEq, Eq, Clone)]
pub enum Type {
    Stream = SOCK_STREAM as isize,
    Datagram = SOCK_DGRAM as isize,
    Raw = SOCK_RAW as isize,
    Sequence = SOCK_SEQPACKET as isize,
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum StreamProtocol {
    TCP = IPPROTO_TCP as isize,
    SCTP = IPPROTO_SCTP as isize,
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum DatagramProtocol {
    UDP = IPPROTO_UDP as isize,
    L2TP = 115,
    UDPLite = IPPROTO_UDPLITE as isize,
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum Protocol {
    Null,
    Layer2Protocol(u16),
    Layer3Protocol(u8),
    StreamProtocol(StreamProtocol),
    DatagramProtocol(DatagramProtocol),
}

impl Protocol {
    pub fn into_inner(&self) -> isize {
        match *self {
            Protocol::Layer2Protocol(i) => i as isize,
            Protocol::Layer3Protocol(j) => j as isize,
            Protocol::StreamProtocol(l) => l.clone() as isize,
            Protocol::DatagramProtocol(k) => k.clone() as isize,
            Protocol::Null => 0,
        }
    }
}

const DOMAIN_PACKET: Domain = Domain::Packet;
const TYPE_RAW: Type = Type::Raw;
const ETH_P_ALL: u16 = 0x0003;
const PROTOCOL_ETH_ALL: Protocol = Protocol::Layer2Protocol(ETH_P_ALL.to_be());

pub struct PacketLayer2Socket {
    fd: i32,
}

trait Socket {
    fn os(&self) -> i32;
}

impl PacketLayer2Socket {
    #[cfg(target_os = "linux")]
    pub fn new() -> Result<Self> {
        Self::with_flags(SOCK_CLOEXEC)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn new() -> Result<Self> {
        Self::with_flags(0)
    }

    #[cfg(target_os = "linux")]
    pub fn plain() -> Result<Self> {
        Self::with_flags(0)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn plain() -> Result<Self> {
        Self::new()
    }

    #[cfg(target_os = "linux")]
    pub fn nonblocking() -> Result<Self> {
        Self::with_flags(SOCK_CLOEXEC | SOCK_NONBLOCK)
    }

    #[cfg(target_os = "linux")]
    pub fn plain_nonblocking() -> Result<Self> {
        Self::with_flags(SOCK_NONBLOCK)
    }

    fn with_flags(flags: i32) -> Result<Self> {
        match unsafe {
            cvt(socket(
                DOMAIN_PACKET as i32,
                TYPE_RAW as i32 | flags,
                PROTOCOL_ETH_ALL.into_inner() as i32,
            ))
        } {
            Ok(fd) => Ok(Self { fd }),
            Err(e) => Err(e),
        }
    }
}

impl Drop for PacketLayer2Socket {
    fn drop(&mut self) {
        loop {
            match unsafe { cvt(close(self.os())) } {
                Ok(_) => return,
                Err(e) => {
                    if e.kind() == Interrupted {
                        continue;
                    } else {
                        unreachable!();
                    }
                }
            }
        }
    }
}

impl Socket for PacketLayer2Socket {
    #[inline]
    fn os(&self) -> i32 {
        self.fd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }

    #[test]
    fn packet_layer2_socket_new() {
        let s = PacketLayer2Socket::new().unwrap();
        assert!(s.os() >= 0);
    }

    #[test]
    fn packet_layer2_socket_plain() {
        let s = PacketLayer2Socket::plain().unwrap();
        assert!(s.os() >= 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn packet_layer2_socket_nonblocking() {
        let s = PacketLayer2Socket::nonblocking().unwrap();
        assert!(s.os() >= 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn packet_layer2_socket_plain_nonblocking() {
        let s = PacketLayer2Socket::plain_nonblocking().unwrap();
        assert!(s.os() >= 0);
    }
}
