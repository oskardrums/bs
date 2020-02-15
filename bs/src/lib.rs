//! Safe, sound, low-level socket operations
//!
//! Provides a [full sockets API](socket/index.html) with optional support for [flexible kernel packet
//! filtering](filter/index.html).
//! # Examples
//! ```ignore
//! # use bs_system::Result;
//! # use bs_system::SystemError as Error;
//! # use bs_socket::socket::{BasicSocket, SetFilter};
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
//!     let got_this_many_bytes = s.receive(buffer, 0)?;
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
#[cfg(feature = "filter")]
pub mod filter {
    // XXX
    #[doc(hidden)]
    pub mod classic {
        use bs_cbpf::SocketFilterProgram;
        use bs_filter::backend::Classic as Backend;
        use bs_filter::idiom;
        use bs_filter::Predicate;
        use eui48::MacAddress;
        use std::net::IpAddr;

        pub type Filter = Predicate<Backend>;
        pub type Attach = SocketFilterProgram;

        pub fn arp() -> Filter {
            idiom::ethernet::ether_type_arp::<Backend>()
        }

        pub fn ether_src(mac: MacAddress) -> Filter {
            idiom::ethernet::ether_src::<Backend>(mac)
        }

        pub fn ether_host(mac: MacAddress) -> Filter {
            idiom::ethernet::ether_host::<Backend>(mac)
        }

        pub fn ip_host(ip: IpAddr) -> Filter {
            idiom::ip::ip_host::<Backend>(ip)
        }
    }

    // XXX
    #[doc(hidden)]
    #[cfg(feature = "ebpf")]
    pub mod extended {
        use bs_ebpf::SocketFilterFd;
        use bs_filter::backend::Extended;
        use bs_filter::idiom;
        use bs_filter::Predicate;
        use eui48::MacAddress;
        use std::net::IpAddr;

        pub type Filter = Predicate<Extended>;
        pub type Attach = SocketFilterFd;

        pub fn arp() -> Filter {
            idiom::ethernet::ether_type_arp::<Extended>()
        }

        pub fn ether_src(mac: MacAddress) -> Filter {
            idiom::ethernet::ether_src::<Extended>(mac)
        }

        pub fn ether_host(mac: MacAddress) -> Filter {
            idiom::ethernet::ether_host::<Extended>(mac)
        }

        pub fn ip_host(ip: IpAddr) -> Filter {
            idiom::ip::ip_host::<Extended>(ip)
        }
    }
}

/// Main sockets API
///
/// see `bs-socket` for more information
pub mod socket {
    #[cfg(feature = "filter")]
    pub use bs_socket::filter;
    #[cfg(target_os = "linux")]
    pub use bs_socket::packet;
    pub use bs_socket::raw;
    pub use bs_socket::socket;
    pub use bs_socket::tcp;
    pub use bs_socket::udp;
}

// TODO - remove this attribute and add non-linux tests
#[cfg(target_os = "linux")]
#[cfg(test)]
mod tests {
    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    use crate::filter::classic;
    use crate::socket::filter::{AttachFilter, SetFilter};
    use crate::socket::packet;
    use crate::socket::socket::Socket;
    use cfg_if::cfg_if;

    cfg_if! { if #[cfg(feature = "ebpf")] {
    use crate::filter::extended;
    use crate::socket::socket::Socket;

    #[test]
    fn packet_socket_extended_arp_filter() {
        init();
        let mut s: Socket<packet::PacketLayer2Socket> = Socket::new().unwrap();
        let f = extended::Attach::from_instructions(extended::arp().compile().unwrap()).unwrap();
        let _ = s
            .set_filter::<classic::Attach, extended::Attach>(f)
            .unwrap();
    }

    #[test]
    fn packet_socket_extended_ip_host() {
        init();
        let mut s: Socket<packet::PacketLayer2Socket> = Socket::new().unwrap();
        let f = extended::Attach::from_instructions(
            extended::ip_host("1.1.1.1".parse().unwrap())
                .compile()
                .unwrap(),
        )
        .unwrap();
        let _ = s
            .set_filter::<classic::Attach, extended::Attach>(f)
            .unwrap();

        init();
        let mut s: Socket<packet::PacketLayer2Socket> = Socket::new().unwrap();
        let f = extended::Attach::from_instructions(
            extended::ip_host("::1".parse().unwrap()).compile().unwrap(),
        )
        .unwrap();
        let _ = s
            .set_filter::<classic::Attach, extended::Attach>(f)
            .unwrap();
    }
    }}

    cfg_if! { if #[cfg(feature = "filter")] {
        #[test]
        fn packet_socket_arp_filter() {
            init();
            let mut s: Socket<packet::PacketLayer2Socket> = Socket::new().unwrap();
            let f = classic::Attach::from_instructions(classic::arp().compile().unwrap()).unwrap();
            let _ = s.set_filter::<classic::Attach, classic::Attach>(f).unwrap();
        }

        #[test]
        fn packet_socket_ether_src() {
            init();
            let mut s: Socket<packet::PacketLayer2Socket> = Socket::new().unwrap();
            let f = classic::Attach::from_instructions(
                classic::ether_src("00:11:22:33:44:55".parse().unwrap())
                    .compile()
                    .unwrap(),
            )
            .unwrap();
            let _ = s.set_filter::<classic::Attach, classic::Attach>(f).unwrap();
        }

        #[test]
        fn packet_socket_ether_host() {
            init();
            let mut s: Socket<packet::PacketLayer2Socket> = Socket::new().unwrap();
            let f = classic::Attach::from_instructions(
                classic::ether_host("00:11:22:33:44:55".parse().unwrap())
                    .compile()
                    .unwrap(),
            )
            .unwrap();
            let _ = s.set_filter::<classic::Attach, classic::Attach>(f).unwrap();
        }

        #[test]
        fn packet_socket_ip_host() {
            init();
            let mut s: Socket<packet::PacketLayer2Socket> = Socket::new().unwrap();
            let f = classic::Attach::from_instructions(
                classic::ip_host("1.1.1.1".parse().unwrap())
                    .compile()
                    .unwrap(),
            )
            .unwrap();
            let _ = s.set_filter::<classic::Attach, classic::Attach>(f).unwrap();


    //        let mut buf: [u8;1024] = [0;1024];
    //        let _ = s.receive(&mut buf, 0);

            init();
            let mut s: Socket<packet::PacketLayer2Socket> = Socket::new().unwrap();
            let f = classic::Attach::from_instructions(
                classic::ip_host("::1".parse().unwrap()).compile().unwrap(),
            )
            .unwrap();
            let _ = s.set_filter::<classic::Attach, classic::Attach>(f).unwrap();
        }
        }}
}
