use crate::socket::SocketDesc;
use libc::{AF_PACKET, ETH_P_ALL, SOCK_DGRAM, SOCK_RAW};
use std::os::unix::io::RawFd;

pub struct PacketLayer2Socket {
    fd: RawFd,
}

impl SocketDesc for PacketLayer2Socket {
    fn new(fd: RawFd) -> Self {
        Self { fd }
    }
    fn domain() -> i32 {
        AF_PACKET as i32
    }
    fn type_() -> i32 {
        SOCK_RAW as i32
    }
    fn protocol() -> i32 {
        (ETH_P_ALL as u16).to_be() as i32
    }
    fn os(&self) -> i32 {
        self.fd
    }
}

pub struct PacketLayer3Socket {
    fd: RawFd,
}

impl SocketDesc for PacketLayer3Socket {
    fn new(fd: RawFd) -> Self {
        Self { fd }
    }
    fn domain() -> i32 {
        AF_PACKET as i32
    }
    fn type_() -> i32 {
        SOCK_DGRAM as i32
    }
    fn protocol() -> i32 {
        (ETH_P_ALL as u16).to_be() as i32
    }
    fn os(&self) -> i32 {
        self.fd
    }
}
