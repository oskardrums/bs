//! Sockets-related structs and functionality for `bs`

#![deny(
    bad_style,
    const_err,
    dead_code,
    improper_ctypes,
    non_shorthand_field_patterns,
    no_mangle_generic_items,
    overflowing_literals,
    path_statements,
    patterns_in_fns_without_body,
    private_in_public,
    unconditional_recursion,
    unused,
    unused_allocation,
    unused_comparisons,
    unused_parens,
    while_true,
    missing_debug_implementations,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results,
    missing_copy_implementations
)]

/// `packet(7)` sockets
pub mod packet;
/// `raw(7)` sockets
pub mod raw;
/// `Socket` struct and implementation
pub mod socket;
/// `tcp(7)` sockets
pub mod tcp;
/// `udp(7)` sockets
pub mod udp;

#[cfg(test)]
mod tests {
    use super::packet::*;
    use super::raw::*;
    use super::socket::*;
    use super::tcp::*;
    use super::udp::*;
    use bs_filter::backend::Classic;
    use bs_filter::idiom::ethernet::ether_type_arp;
    use libc::SOCK_NONBLOCK;

    #[test]
    #[allow(unused_results)]
    fn set_classic_filter() {
        // UDP is arbitrary here
        let mut s: Socket<UdpSocket> = Socket::new().unwrap();
        let p = ether_type_arp::<Classic>();
        let f = p.compile().unwrap().build().unwrap();
        s.set_filter(f).unwrap();
    }

    /*
    #[test]
    fn set_extended_filter() {
        let mut s: Socket<PacketLayer2Socket> = Socket::new().unwrap();
        let mut buf = [0; 1024];
        let ip = "1.1.1.1".parse().unwrap();
        let p = ebpf::ip_host(ip);
        let f = p.compile();
        s.set_filter(Extended(f)).unwrap();
        s.recv(&mut buf, 0);
    }
    */

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
