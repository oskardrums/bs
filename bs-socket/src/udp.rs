use crate::socket::SocketKind;
use crate::socket::PROTO_NULL;
use libc::{AF_INET, SOCK_DGRAM};
use std::os::unix::io::RawFd;

/// `udp(7)` over `ip(7)`
#[derive(Debug, Copy, Clone)]
pub struct UdpSocket {
    fd: RawFd,
}

impl SocketKind for UdpSocket {
    fn new(fd: RawFd) -> Self {
        Self { fd }
    }
    fn domain() -> i32 {
        AF_INET
    }
    fn type_() -> i32 {
        SOCK_DGRAM
    }
    fn protocol() -> i32 {
        PROTO_NULL
    }
    fn os(&self) -> i32 {
        self.fd
    }
}
