//! Safe, sound, low-level socket operations
//!
//! Provides a [full sockets API](socket/index.html) with optional support for [flexible kernel packet
//! filtering](filter/index.html).
//! # Examples
//! ```
//! # use bs_system::Result;
//! # use bs_system::SystemError as Error;
//! # use std::net::IpAddr;
//! # use eui48::MacAddress;
//! use bs::{
//!     filter::{
//!         backend::Classic,
//!         idiom::{
//!             ip::ip_src,
//!             ethernet::ether_src,
//!         },
//!     },
//!     socket::{
//!         socket::Socket,
//!         packet::PacketLayer2Socket,
//!     },
//! };
//!
//! # const IP_HEADER_LENGTH: usize = 20;
//! # const IP_SOURCE_START: usize = 12;
//! # const IP_SOURCE_END: usize = IP_SOURCE_START + 4;
//! # const PARSE_ERROR: i32 = 0;
//!
//! fn raw_ethernet_only_loves_one_one_one_one(buffer: &mut [u8]) -> Result<()> {
//!
//!     let vip = "1.1.1.1".parse().map_err(|_| Error(PARSE_ERROR))?;
//!     let my_gateway = "00:11:22:33:44:55".parse().map_err(|_| Error(PARSE_ERROR))?;
//!
//!     let mut s: Socket<PacketLayer2Socket> = Socket::new()?;
//!
//!     s.set_filter(
//!         ( ip_src::<Classic>(vip) & ether_src(my_gateway) )
//!             .compile()?
//!             .build()?
//!     )?;
//!
//!     let got_this_many_bytes = s.recv(buffer, 0)?;
//!
//!     assert!(got_this_many_bytes > IP_HEADER_LENGTH);
//!     assert_eq!([1, 1, 1, 1], buffer[IP_SOURCE_START..IP_SOURCE_END]);
//!
//!     Ok(())
//! }
//!```

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



/// Packet filtering related structs and functionality
///
/// see `bs-filter` for more information
#[cfg(feature = "bs-filter")]
pub mod filter {
    pub use bs_filter::backend;
    pub use bs_filter::idiom;
}

/// Main sockets API
///
/// see `bs-socket` for more information
pub mod socket {
    #[cfg(target_os = "linux")]
    pub use bs_socket::packet;
    pub use bs_socket::raw;
    pub use bs_socket::socket;
    pub use bs_socket::tcp;
    pub use bs_socket::udp;
}

/// Run tests only on linux while all tests are only linux anyway.
#[cfg(target_os = "linux")]
#[cfg(test)]
mod tests {
    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    use super::filter::*;
    use super::socket::*;

    #[cfg(all(target_os = "linux", feature = "bs-filter"))]
    #[test]
    fn packet_socket_arp_filter() {
        let mut s: socket::Socket<packet::PacketLayer2Socket> = socket::Socket::new().unwrap();
        let p = idiom::ethernet::ether_type_arp::<backend::Classic>();
        let f = p.compile().unwrap().build().unwrap();
        let _ = s.set_filter(f).unwrap();
    }

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    #[test]
    fn packet_socket_ebpf_arp_filter() {
        let mut s: socket::Socket<packet::PacketLayer2Socket> = socket::Socket::new().unwrap();
        let p = idiom::ethernet::ether_type_arp::<backend::Extended>();
        let f = p.compile().unwrap().build().unwrap();
        let _ = s.set_filter(f).unwrap();
    }

    #[cfg(all(target_os = "linux", feature = "bs-filter"))]
    #[test]
    fn packet_socket_ether_src() {
        init();
        let mut s: socket::Socket<packet::PacketLayer2Socket> = socket::Socket::new().unwrap();
        let p =
            idiom::ethernet::ether_src::<backend::Classic>("00:11:22:33:44:55".parse().unwrap());
        let f = p.compile().unwrap().build().unwrap();
        let _ = s.set_filter(f).unwrap();
    }

    #[cfg(all(target_os = "linux", feature = "bs-filter"))]
    #[test]
    fn packet_socket_ether_host() {
        init();
        let mut s: socket::Socket<packet::PacketLayer2Socket> = socket::Socket::new().unwrap();
        let p =
            idiom::ethernet::ether_host::<backend::Classic>("00:11:22:33:44:55".parse().unwrap());
        let f = p.compile().unwrap().build().unwrap();
        let _ = s.set_filter(f).unwrap();
    }

    #[cfg(all(target_os = "linux", feature = "bs-filter"))]
    #[test]
    fn packet_socket_ip_host() {
        init();
        let mut s: socket::Socket<packet::PacketLayer2Socket> = socket::Socket::new().unwrap();
        let _ = s.set_filter(
            idiom::ip::ip_host::<backend::Classic>("1.1.1.1".parse().unwrap())
                .compile()
                .unwrap()
                .build()
                .unwrap(),
        );

        let _ = s.set_filter(
            idiom::ip::ip_host::<backend::Classic>("::1".parse().unwrap())
                .compile()
                .unwrap()
                .build()
                .unwrap(),
        );

        //      let mut buf: [u8;1024] = [0;1024];
        //      let _ = s.recv(&mut buf, 0);
    }

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    #[test]
    fn packet_socket_ebpf_ip_host() {
        init();
        let mut s: socket::Socket<packet::PacketLayer2Socket> = socket::Socket::new().unwrap();
        let _ = s.set_filter(
            idiom::ip::ip_host::<backend::Extended>("1.1.1.1".parse().unwrap())
                .compile()
                .unwrap()
                .build()
                .unwrap(),
        );
    }
}
