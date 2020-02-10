use crate::backend::Backend;
use crate::predicate::{Expr::*, Predicate};
use crate::util;
use crate::util::{mac_to_u32_and_u16, MacAddress};
use crate::util::{OFFSET_ETHER_DST, OFFSET_ETHER_SRC};
use crate::Condition;
use crate::consts::BPF_JEQ;
use libc::{ETH_P_ARP, ETH_P_IP};  // TODO - move to consts, osx doesn't have it in libc
use std::mem::size_of;

/// true iff packet's ethernet type is `ether_type`
pub fn ether_type<K: Backend>(ether_type: u16) -> Predicate<K> {
    Predicate::from_inner(Terminal(util::ether_type(ether_type)))
}

/// true iff ethernet source is `mac`
pub fn ether_src<K: Backend>(mac: MacAddress) -> Predicate<K> {
    let (foursome, twosome) = mac_to_u32_and_u16(mac);
    Predicate::from_inner(Terminal(Condition::new(
        K::load_u32_at(OFFSET_ETHER_SRC),
        K::Comparison::from(BPF_JEQ as u8),
        K::Value::from(foursome),
    ))) & Predicate::from_inner(Terminal(Condition::new(
        K::load_u16_at(OFFSET_ETHER_SRC + size_of::<u32>() as u32),
        K::Comparison::from(BPF_JEQ as u8),
        K::Value::from(twosome as u32),
    )))
}

/// true iff ethernet destination is `mac`
pub fn ether_dst<K: Backend>(mac: MacAddress) -> Predicate<K> {
    let (foursome, twosome) = mac_to_u32_and_u16(mac);
    Predicate::from_inner(Terminal(Condition::new(
        K::load_u32_at(OFFSET_ETHER_DST),
        K::Comparison::from(BPF_JEQ as u8),
        K::Value::from(foursome),
    ))) & Predicate::from_inner(Terminal(Condition::new(
        K::load_u16_at(OFFSET_ETHER_DST + size_of::<u32>() as u32),
        K::Comparison::from(BPF_JEQ as u8),
        K::Value::from(twosome as u32),
    )))
}

/// true iff `mac` is either the ethernet source or destination of the packet
pub fn ether_host<K: Backend>(mac: MacAddress) -> Predicate<K> {
    ether_dst(mac) | ether_src(mac)
}

/// accepts only ARP packets
pub fn ether_type_arp<K: Backend>() -> Predicate<K> {
    ether_type(ETH_P_ARP as u16)
}

/// accepts only IPv4 packets
pub fn ether_type_ip4<K: Backend>() -> Predicate<K> {
    ether_type(ETH_P_IP as u16)
}
