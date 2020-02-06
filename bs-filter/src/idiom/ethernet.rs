use crate::{util, backend::Backend, predicate::Predicate, Condition, predicate::Expr::*};
use libc::ETH_P_ARP;

pub fn ether_type<K: Backend>(ether_type: u16) -> Predicate<Condition<K>> {
    Predicate::from(Terminal(util::ether_type(ether_type)))
}

pub fn ether_type_arp<K: Backend>() -> Predicate<Condition<K>> {
    ether_type(ETH_P_ARP as u16)
}
