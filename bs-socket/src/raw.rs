use crate::socket::SocketKind;
use libc::{AF_INET, IPPROTO_RAW, SOCK_RAW};
use std::os::unix::io::RawFd;

/// `raw(7)` layer 3 socket
#[derive(Debug, Clone, Copy)]
pub struct RawSocket {
    fd: RawFd,
}

impl SocketKind for RawSocket {
    fn new(fd: RawFd) -> Self {
        Self { fd }
    }
    fn domain() -> i32 {
        AF_INET
    }
    fn type_() -> i32 {
        SOCK_RAW
    }
    fn protocol() -> i32 {
        IPPROTO_RAW
    }
    fn os(&self) -> i32 {
        self.fd
    }
}
