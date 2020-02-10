use crate::backend::Backend;
use crate::consts::BPF_JEQ;
use crate::predicate::{Expr::*, Predicate};
use crate::util::Ipv4Addr;
use crate::util::{OFFSET_IP_DST, OFFSET_IP_SRC, OFFSET_IP_PROTO};
use crate::Condition;
use crate::idiom::ethernet::ether_type_ip4;

/// true iff packet's IP protocol field is `proto`
pub fn ip_proto<K: Backend>(proto: u8) -> Predicate<K> {
    Predicate::from_inner(Terminal(Condition::new(
        K::load_u8_at(OFFSET_IP_PROTO),
        K::Comparison::from(BPF_JEQ as u8),
        K::Value::from(proto as u32),
    )))

}

/// true iff IP source is `ip`
pub fn ip_src<K: Backend>(ip: Ipv4Addr) -> Predicate<K> {
    ether_type_ip4() &
    Predicate::from_inner(Terminal(Condition::new(
        K::load_u32_at(OFFSET_IP_SRC),
        K::Comparison::from(BPF_JEQ as u8),
        K::Value::from(ip.into()),
    )))
}

/// true iff IP destination is `ip`
pub fn ip_dst<K: Backend>(ip: Ipv4Addr) -> Predicate<K> {
    ether_type_ip4() &
    Predicate::from_inner(Terminal(Condition::new(
        K::load_u32_at(OFFSET_IP_DST),
        K::Comparison::from(BPF_JEQ as u8),
        K::Value::from(ip.into()),
    )))
}

/// true iff `ip` is either IP source or destination
pub fn ip_host<K: Backend>(ip: Ipv4Addr) -> Predicate<K> {
    ip_src(ip) | ip_dst(ip)
}
