//! safe, sound, low-level socket operations

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
    pub use bs_socket::packet;
    pub use bs_socket::raw;
    pub use bs_socket::socket;
    pub use bs_socket::tcp;
    pub use bs_socket::udp;
}


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
}
