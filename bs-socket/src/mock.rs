use crate::socket::SocketKind;
use crate::socket::PROTO_NULL;
use crate::socket::{SetFilter, Socket};
use libc::{AF_INET, SOCK_STREAM};
use std::os::unix::io::RawFd;

#[derive(Debug, Copy, Clone)]
pub struct MockSocket {
    fd: RawFd,
}

impl SocketKind for MockSocket {
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

impl SetFilter for Socket<MockSocket> {}
