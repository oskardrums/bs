use crate::{backend::Backend, predicate::Expr::*, predicate::Predicate, util};
use libc::ETH_P_ARP;

/// true iff packet's ethernet type is `ether_type`
pub fn ether_type<K: Backend>(ether_type: u16) -> Predicate<K> {
    Predicate::from(Terminal(util::ether_type(ether_type)))
}
/// accept only ARP packets
pub fn ether_type_arp<K: Backend>() -> Predicate<K> {
    ether_type(ETH_P_ARP as u16)
}
