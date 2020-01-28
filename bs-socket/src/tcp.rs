use crate::socket::SocketDesc;
use crate::socket::PROTO_NULL;
use libc::{AF_INET, SOCK_STREAM};
use std::os::unix::io::RawFd;

pub struct TcpSocket {
    fd: RawFd,
}

impl SocketDesc for TcpSocket {
    fn new(fd: RawFd) -> Self {
        Self { fd }
    }
    fn domain() -> i32 {
        AF_INET as i32
    }
    fn type_() -> i32 {
        SOCK_STREAM as i32
    }
    fn protocol() -> i32 {
        PROTO_NULL
    }
    fn os(&self) -> i32 {
        self.fd
    }
}
