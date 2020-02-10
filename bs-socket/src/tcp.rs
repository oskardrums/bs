use crate::socket::SocketDesc;
use crate::socket::PROTO_NULL;
use libc::{AF_INET, SOCK_STREAM};
use std::os::unix::io::RawFd;

/// `tcp(7)` over `ip(7)`
#[derive(Debug, Copy, Clone)]
pub struct TcpSocket {
    fd: RawFd,
}

impl SocketDesc for TcpSocket {
    fn new(fd: RawFd) -> Self {
        Self { fd }
    }
    fn domain() -> i32 {
        AF_INET
    }
    fn type_() -> i32 {
        SOCK_STREAM
    }
    fn protocol() -> i32 {
        PROTO_NULL
    }
    fn os(&self) -> i32 {
        self.fd
    }
}
