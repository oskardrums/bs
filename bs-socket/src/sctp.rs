use crate::socket::SocketKind;
use crate::socket::PROTO_NULL;
use libc::{AF_INET, SOCK_SCTP};
use std::os::unix::io::RawFd;

pub struct UdpSocket {
    fd: RawFd,
}

impl SocketKind for SctpSocket {
    fn new(fd: RawFd) -> Self {
        Self { fd }
    }
    fn domain() -> i32 {
        AF_INET
    }
    fn type_() -> i32 {
        SOCK_SCTP
    }
    fn protocol() -> i32 {
        PROTO_NULL
    }
    fn os(&self) -> i32 {
        self.fd
    }
}
