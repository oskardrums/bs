use crate::socket::SocketKind;
use libc::{AF_PACKET, ETH_P_ALL, SOCK_DGRAM, SOCK_RAW};
use std::os::unix::io::RawFd;

/// Raw layer 2 `packet(7)` socket
#[derive(Debug, Clone, Copy)]
pub struct PacketLayer2Socket {
    fd: RawFd,
}

impl SocketKind for PacketLayer2Socket {
    fn new(fd: RawFd) -> Self {
        Self { fd }
    }
    fn domain() -> i32 {
        AF_PACKET
    }
    fn type_() -> i32 {
        SOCK_RAW
    }
    fn protocol() -> i32 {
        (ETH_P_ALL as u16).to_be() as i32
    }
    fn os(&self) -> i32 {
        self.fd
    }
}

/// Raw layer 3 `packet(7)` socket
#[derive(Debug, Clone, Copy)]
pub struct PacketLayer3Socket {
    fd: RawFd,
}

impl SocketKind for PacketLayer3Socket {
    fn new(fd: RawFd) -> Self {
        Self { fd }
    }
    fn domain() -> i32 {
        AF_PACKET
    }
    fn type_() -> i32 {
        SOCK_DGRAM
    }
    fn protocol() -> i32 {
        (ETH_P_ALL as u16).to_be() as i32
    }
    fn os(&self) -> i32 {
        self.fd
    }
}
