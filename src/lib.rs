use cvt::cvt;
use libc::{
    c_void, close, fcntl, setsockopt, socket, socklen_t, AF_INET, AF_INET6, AF_PACKET, AF_UNIX,
    ETH_P_ALL, FD_CLOEXEC, F_GETFD, F_GETFL, F_SETFD, F_SETFL, IPPROTO_RAW, IPPROTO_SCTP,
    IPPROTO_TCP, IPPROTO_UDP, IPPROTO_UDPLITE, O_NONBLOCK, SOCK_DGRAM, SOCK_RAW, SOCK_SEQPACKET,
    SOCK_STREAM, SOL_SOCKET, SO_ATTACH_FILTER,
};

pub mod predicate;
pub mod filter;

#[cfg(target_os = "linux")]
use libc::{SOCK_CLOEXEC, SOCK_NONBLOCK};
use std::io::ErrorKind::Interrupted;
use std::io::Result;
use std::mem::size_of_val;

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

    pub fn attach_filter(&mut self, prog: cbpf::Prog) -> Result<()> {
        match unsafe {
            cvt(setsockopt(
                self.os(),
                SOL_SOCKET,
                SO_ATTACH_FILTER,
                &prog as *const _ as *const c_void,
                size_of_val(&prog) as socklen_t,
            ))
        } {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub fn recv(&self, buf: &mut [u8], flags: i32) -> Result<usize> {
        unsafe {
            let n = cvt({
                libc::recv(
                    self.os(),
                    buf.as_mut_ptr() as *mut c_void,
                    buf.len(),
                    flags,
                )
            })?;
            Ok(n as usize)
        }
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
    use bpf;
    pub use std::mem::{forget, size_of_val};

    const BPF_LD: u16 = 0x00;
    const BPF_LDX: u16 = 0x01;
    const BPF_ST: u16 = 0x02;
    const BPF_STX: u16 = 0x03;
    const BPF_ALU: u16 = 0x04;
    const BPF_JMP: u16 = 0x05;
    const BPF_RET: u16 = 0x06;
    const BPF_MISC: u16 = 0x07;
    const BPF_W: u16 = 0x00;
    const BPF_H: u16 = 0x08;
    const BPF_B: u16 = 0x10;
    const BPF_IMM: u16 = 0x00;
    const BPF_ABS: u16 = 0x20;
    const BPF_IND: u16 = 0x40;
    const BPF_MEM: u16 = 0x60;
    const BPF_LEN: u16 = 0x80;
    const BPF_MSH: u16 = 0xa0;
    const BPF_ADD: u16 = 0x00;
    const BPF_SUB: u16 = 0x10;
    const BPF_MUL: u16 = 0x20;
    const BPF_DIV: u16 = 0x30;
    const BPF_OR: u16 = 0x40;
    const BPF_AND: u16 = 0x50;
    const BPF_LSH: u16 = 0x60;
    const BPF_RSH: u16 = 0x70;
    const BPF_NEG: u16 = 0x80;
    const BPF_MOD: u16 = 0x90;
    const BPF_XOR: u16 = 0xa0;
    const BPF_JA: u16 = 0x00;
    const BPF_JEQ: u16 = 0x10;
    const BPF_JGT: u16 = 0x20;
    const BPF_JGE: u16 = 0x30;
    const BPF_JSET: u16 = 0x40;
    const BPF_K: u16 = 0x00;
    const BPF_X: u16 = 0x08;

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
    pub struct Compiler {}

    #[derive(Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd)]
    pub struct Condition {
        // last Op must be a jump, we should force it
        ops: Vec<Op>,
        return_instruction: u16,
        return_argument: u32,
    }

    impl Condition {
        pub fn new(ops: Vec<Op>, return_instruction: u16, return_argument: u32) -> Self {
            Self {
                ops,
                return_instruction,
                return_argument,
            }
        }

        pub fn ops(self) -> Vec<Op> {
            self.ops
        }

        pub fn return_argument(&self) -> u32 {
            self.return_argument
        }

        pub fn return_instruction(&self) -> u16 {
            self.return_instruction
        }

        pub fn len(&self) -> u8 {
            (self.ops.len() as u8) + 1 // for good luck. nah, for the return op.
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
        fn walk(&self, expr: Expr<Condition>, out: &mut Vec<Op>, jt: u8, jf: u8) -> u8 {
            let mut res = 0;
            match expr {
                Expr::Terminal(condition) => {
                    out.push(Op::new(
                        condition.return_instruction(),
                        jt,
                        jf,
                        condition.return_argument(),
                    ));
                    res = condition.len();
                    out.extend(condition.ops());
                }
                Expr::Not(e) => {
                    res = self.walk(*e, out, jf, jt);
                }
                Expr::And(a, b) => {
                    res = self.walk(*b, out, jt, jf);
                    res += self.walk(*a, out, 0, jf + res);
                }
                Expr::Or(a, b) => {
                    res = self.walk(*b, out, jt, jf);
                    res += self.walk(*a, out, jt + res, 0);
                }
                Expr::Const(boolean) => {
                    if boolean {
                    } else {
                    }
                }
            };
            res
        }

        pub fn compile(&self, expr: Expr<Condition>) -> Prog {
            let mut instructions: Vec<Op> = Vec::new();

            instructions.push(Op::new(BPF_RET, 0, 0, 0));
            instructions.push(Op::new(BPF_RET, 0, 0, 4096));
            self.walk(expr, &mut instructions, 0, 1);

            instructions.reverse();
            println!("{:?}", instructions);
            Prog::new(instructions)
        }
    }
    use std::net::Ipv4Addr;
    pub fn ip_dst(ip: Ipv4Addr) -> Expr<Condition> {
        Expr::And(
            Box::new(Expr::Terminal(ether_type(0x0800))),
            Box::new(Expr::Terminal(Condition::new(
                vec![Op::new(BPF_ABS | BPF_LD | BPF_W, 0, 0, 30)],
                BPF_JMP | BPF_JEQ,
                ip.into(),
            ))),
        )
    }

    pub fn ether_type(ether_type: u16) -> Condition {
        Condition::new(
            vec![Op::new(BPF_ABS | BPF_LD | BPF_H, 0, 0, 0x000c)],
            BPF_JMP | BPF_JEQ,
            ether_type as u32,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::cbpf::*;
    use super::*;
    #[test]
    fn doit() {
        let compiler = Compiler::default();
        compiler.compile(Expr::And(
            Box::new(Expr::Terminal(ether_type(0x0800))),
            Box::new(Expr::Terminal(ether_type(0x0806))),
        ));
        compiler.compile(Expr::Or(
            Box::new(Expr::Terminal(ether_type(0x0800))),
            Box::new(Expr::Terminal(ether_type(0x0806))),
        ));
    }

    #[test]
    fn attach_filter() {
        let mut s: Socket<PacketLayer2Socket> = Socket::new().unwrap();
        let mut buf = [0; 10];
        s.attach_filter(Compiler::default().compile(cbpf::ip_dst("1.1.1.1".parse().unwrap())));
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
