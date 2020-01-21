use cvt::cvt;
use libc::{
    close, fcntl, socket, AF_INET, AF_INET6, AF_PACKET, AF_UNIX, ETH_P_ALL, FD_CLOEXEC, F_GETFD,
    F_GETFL, F_SETFD, F_SETFL, IPPROTO_RAW, IPPROTO_SCTP, IPPROTO_TCP, IPPROTO_UDP,
    IPPROTO_UDPLITE, O_NONBLOCK, SOCK_DGRAM, SOCK_RAW, SOCK_SEQPACKET, SOCK_STREAM,
};

#[cfg(target_os = "linux")]
use libc::{SOCK_CLOEXEC, SOCK_NONBLOCK};
use std::io::ErrorKind::Interrupted;
use std::io::Result;

pub const PROTO_NULL: i32 = 0_i32;
pub const IPPROTO_L2TP: i32 = 115_i32;

pub trait SocketDesc {
    fn new(fd: i32) -> Self;
    fn os(&self) -> i32;
    fn domain() -> i32;
    fn type_() -> i32;
    fn protocol() -> i32;
}

impl<S: SocketDesc> Socket<S> {
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

    #[cfg(not(target_os = "linux"))]
    pub fn nonblocking() -> Result<Self> {
        let mut s = Self::new()?;
        s.set_nonblocking()?;
        s
    }

    #[cfg(target_os = "linux")]
    pub fn plain_nonblocking() -> Result<Self> {
        Self::with_flags(SOCK_NONBLOCK)
    }

    fn with_flags(flags: i32) -> Result<Self> {
        match unsafe { cvt(socket(S::domain(), S::type_() | flags, S::protocol())) } {
            Ok(fd) => Ok(Self {
                inner: S::new(fd as i32),
            }),
            Err(e) => Err(e),
        }
    }

    pub fn os(&self) -> i32 {
        self.inner.os()
    }

    pub fn flags(&self) -> Result<i32> {
        unsafe { cvt(fcntl(self.os(), F_GETFL)) }
    }

    pub fn fd_flags(&self) -> Result<i32> {
        unsafe { cvt(fcntl(self.os(), F_GETFD)) }
    }

    pub fn set_nonblocking(&mut self) -> Result<()> {
        self.set_flags(self.flags()? | O_NONBLOCK)
    }

    pub fn set_cloexe(&mut self) -> Result<()> {
        self.set_fd_flags(FD_CLOEXEC)
    }

    fn set_flags(&mut self, flags: i32) -> Result<()> {
        match unsafe { cvt(fcntl(self.os(), F_SETFL, flags)) } {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn set_fd_flags(&mut self, flags: i32) -> Result<()> {
        match unsafe { cvt(fcntl(self.os(), F_SETFD, flags)) } {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

pub struct Socket<S: SocketDesc> {
    inner: S,
}

impl<S: SocketDesc> Drop for Socket<S> {
    fn drop(&mut self) {
        loop {
            match unsafe { cvt(close(self.inner.os())) } {
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

pub struct PacketLayer2Socket {
    fd: i32,
}

impl SocketDesc for PacketLayer2Socket {
    fn new(fd: i32) -> Self {
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
    fd: i32,
}

impl SocketDesc for PacketLayer3Socket {
    fn new(fd: i32) -> Self {
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

pub struct UdpSocket {
    fd: i32,
}

impl SocketDesc for UdpSocket {
    fn new(fd: i32) -> Self {
        Self { fd }
    }
    fn domain() -> i32 {
        AF_INET as i32
    }
    fn type_() -> i32 {
        SOCK_DGRAM as i32
    }
    fn protocol() -> i32 {
        PROTO_NULL
    }
    fn os(&self) -> i32 {
        self.fd
    }
}

pub struct TcpSocket {
    fd: i32,
}

impl SocketDesc for TcpSocket {
    fn new(fd: i32) -> Self {
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

mod cbpf {
    pub use boolean_expression::*;
    pub use std::mem::{forget, size_of_val};

    #[repr(C)]
    #[derive(Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd)]
    pub struct Op {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    }

    impl Op {
        pub fn new(code: u16, jt: u8, jf: u8, k: u32) -> Op {
            Op {
                code: code,
                jt: jt,
                jf: jf,
                k: k,
            }
        }
    }

    #[repr(C)]
    #[derive(Debug)]
    pub struct Prog {
        len: u16,
        filter: *mut Op,
    }

    impl Prog {
        pub fn new(ops: Vec<Op>) -> Prog {
            let mut ops = ops.into_boxed_slice();
            let len = ops.len();
            let ptr = ops.as_mut_ptr();

            forget(ops);

            Prog {
                len: len as _,
                filter: ptr,
            }
        }
    }

    impl Drop for Prog {
        fn drop(&mut self) {
            unsafe {
                let len = self.len as usize;
                let ptr = self.filter;
                Vec::from_raw_parts(ptr, len, len);
            }
        }
    }

    #[derive(Default)]
    pub struct CompilerState {}

    #[derive(Default)]
    pub struct Compiler {
        state: CompilerState,
    }

    #[derive(Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd)]
    pub struct Condition {
        // last Op must be a jump, we should force it
        ops: Vec<Op>,
    }

    impl Condition {
        pub fn new(ops: Vec<Op>) -> Self {
            Self { ops }
        }
    }

    impl IntoIterator for Condition {
        type Item = Op;
        type IntoIter = std::vec::IntoIter<Self::Item>;
        fn into_iter(self) -> Self::IntoIter {
            self.ops.into_iter()
        }
    }

    impl Compiler {
        fn step(&self, expr: Expr<Condition>, instructions: &mut Vec<Op>) {
            match expr {
                Expr::Terminal(c) => instructions.extend(c),
                _ => panic!(),
            }
        }

        pub fn compile(self, expr: Expr<Condition>) -> Prog {
            let mut instructions: Vec<Op> = Vec::new();
            self.step(expr, &mut instructions);
            println!("{:?}", instructions);
            Prog::new(instructions)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::cbpf::*;
    use super::*;
    #[test]
    fn doit() {
        let mut ops = vec![
                Op::new(0x28, 0, 0, 0x000c),
                Op::new(0x15, 0, 1, 0x0806),
                Op::new(0x06, 0, 0, 0xffff),
                Op::new(0x06, 0, 0, 0x0000),
            ];
        let mut c = Condition::new(ops);
        let compiler = Compiler::default();
        println!("{:?}", compiler.compile(Expr::Terminal(c)));
    }

    #[test]
    fn packet_layer2_socket_flags() {
        let mut s: Socket<PacketLayer2Socket> = Socket::plain().unwrap();
        s.set_nonblocking().unwrap();
        assert!(s.flags().unwrap() & SOCK_NONBLOCK == SOCK_NONBLOCK);
    }

    #[test]
    fn packet_layer2_socket_new() {
        let s: Socket<PacketLayer2Socket> = Socket::new().unwrap();
        assert!(s.os() >= 0);
    }

    #[test]
    fn packet_layer2_socket_plain() {
        let s: Socket<PacketLayer2Socket> = Socket::plain().unwrap();
        assert!(s.os() >= 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn packet_layer2_socket_nonblocking() {
        let s: Socket<PacketLayer2Socket> = Socket::nonblocking().unwrap();
        assert!(s.os() >= 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn packet_layer2_socket_plain_nonblocking() {
        let s: Socket<PacketLayer2Socket> = Socket::plain_nonblocking().unwrap();
        assert!(s.os() >= 0);
    }

    #[test]
    fn packet_layer3_socket_new() {
        let s: Socket<PacketLayer2Socket> = Socket::new().unwrap();
        assert!(s.os() >= 0);
    }

    #[test]
    fn packet_layer3_socket_plain() {
        let s: Socket<PacketLayer2Socket> = Socket::plain().unwrap();
        assert!(s.os() >= 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn packet_layer3_socket_nonblocking() {
        let s: Socket<PacketLayer2Socket> = Socket::nonblocking().unwrap();
        assert!(s.os() >= 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn packet_layer3_socket_plain_nonblocking() {
        let s: Socket<PacketLayer2Socket> = Socket::plain_nonblocking().unwrap();
        assert!(s.os() >= 0);
    }

    #[test]
    fn raw_socket_new() {
        let s: Socket<RawSocket> = Socket::new().unwrap();
        assert!(s.os() >= 0);
    }

    #[test]
    fn raw_socket_plain() {
        let s: Socket<RawSocket> = Socket::plain().unwrap();
        assert!(s.os() >= 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn raw_socket_nonblocking() {
        let s: Socket<RawSocket> = Socket::nonblocking().unwrap();
        assert!(s.os() >= 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn raw_socket_plain_nonblocking() {
        let s: Socket<RawSocket> = Socket::plain_nonblocking().unwrap();
        assert!(s.os() >= 0);
    }

    #[test]
    fn udp_socket_new() {
        let s: Socket<UdpSocket> = Socket::new().unwrap();
        assert!(s.os() >= 0);
    }

    #[test]
    fn udp_socket_plain() {
        let s: Socket<UdpSocket> = Socket::plain().unwrap();
        assert!(s.os() >= 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn udp_socket_nonblocking() {
        let s: Socket<UdpSocket> = Socket::nonblocking().unwrap();
        assert!(s.os() >= 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn udp_socket_plain_nonblocking() {
        let s: Socket<UdpSocket> = Socket::plain_nonblocking().unwrap();
        assert!(s.os() >= 0);
    }

    #[test]
    fn tcp_socket_new() {
        let s: Socket<TcpSocket> = Socket::new().unwrap();
        assert!(s.os() >= 0);
    }

    #[test]
    fn tcp_socket_plain() {
        let s: Socket<TcpSocket> = Socket::plain().unwrap();
        assert!(s.os() >= 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tcp_socket_nonblocking() {
        let s: Socket<TcpSocket> = Socket::nonblocking().unwrap();
        assert!(s.os() >= 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tcp_socket_plain_nonblocking() {
        let s: Socket<TcpSocket> = Socket::plain_nonblocking().unwrap();
        assert!(s.os() >= 0);
    }
}
