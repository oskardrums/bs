#[cfg(feature="bs-filter")]
pub mod filter {
    pub use bs_filter::backend;
    pub use bs_filter::idiom;
    pub use bs_filter::Compile;
}

pub mod socket {
    pub use bs_socket::packet;
    pub use bs_socket::raw;
    pub use bs_socket::tcp;
    pub use bs_socket::udp;
    pub use bs_socket::socket;
}

#[cfg(test)]
mod tests {
    use super::filter::*;
    use super::socket::*;

    #[cfg(all(target_os = "linux", feature = "bs-filter"))]
    #[test]
    fn packet_socket_arp_filter() {
        let mut s: socket::Socket<packet::PacketLayer2Socket> = socket::Socket::new().unwrap();
        let p = idiom::ethernet::ether_type_arp::<backend::Classic>();
        let f = p.compile();
        s.set_filter(f).unwrap();
    }
}
