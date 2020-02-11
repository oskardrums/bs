use crate::backend::Backend;
use crate::predicate::Predicate;
use crate::util::Ipv4Addr;
use crate::util::{OFFSET_IP_DST, OFFSET_IP_SRC, OFFSET_IP_PROTO};
use crate::idiom::ethernet::ether_type_ip4;
use crate::idiom::shift_offset_equals_u8;
use crate::idiom::shift_offset_equals_u32;

/// true iff packet's IP protocol field is `proto`, assuming IP layer starts at offset `shift`
pub fn shift_ip_proto<K: Backend>(proto: u8, shift: u32) -> Predicate<K> {
    shift_offset_equals_u8(OFFSET_IP_PROTO, proto, shift)
}

/// true iff packet's IP protocol field is `proto`
pub fn ip_proto<K: Backend>(proto: u8) -> Predicate<K> {
    shift_ip_proto(proto, 0)
}

/// true iff IP source is `ip`, assuming IP layer starts at offset `shift`
pub fn shift_ip_src<K: Backend>(ip: Ipv4Addr, shift: u32) -> Predicate<K> {
    shift_offset_equals_u32(OFFSET_IP_SRC, ip.into(), shift)
}

/// true iff IP source is `ip`
pub fn ip_src<K: Backend>(ip: Ipv4Addr) -> Predicate<K> {
    ether_type_ip4() &
    shift_ip_src(ip, 0)
}

/// true iff IP destination is `ip`, assuming IP layer starts at offset `shift`
pub fn shift_ip_dst<K: Backend>(ip: Ipv4Addr, shift: u32) -> Predicate<K> {
    shift_offset_equals_u32(OFFSET_IP_DST, ip.into(), shift)
}

/// true iff IP destination is `ip`
pub fn ip_dst<K: Backend>(ip: Ipv4Addr) -> Predicate<K> {
    ether_type_ip4() &
    shift_ip_dst(ip, 0)
}

/// true iff either IP destination or source is `ip`, assuming IP layer starts at offset `shift`
pub fn shift_ip_host<K: Backend>(ip: Ipv4Addr, shift: u32) -> Predicate<K> {
    shift_ip_src(ip, shift) | shift_ip_dst(ip, shift)
}


/// true iff `ip` is either IP source or destination
pub fn ip_host<K: Backend>(ip: Ipv4Addr) -> Predicate<K> {
    shift_ip_host(ip, 0)
}
