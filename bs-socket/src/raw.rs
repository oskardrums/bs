use crate::socket::SocketDesc;
use libc::{AF_INET, IPPROTO_RAW, SOCK_RAW};

pub struct RawSocket {
    fd: i32,
}

impl SocketDesc for RawSocket {
    fn new(fd: i32) -> Self {
        Self { fd }
    }
    fn domain() -> i32 {
        AF_INET as i32
    }
    fn type_() -> i32 {
        SOCK_RAW as i32
    }
    fn protocol() -> i32 {
        IPPROTO_RAW
    }
    fn os(&self) -> i32 {
        self.fd
    }
}
