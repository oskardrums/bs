use crate::condition_builder::ConditionBuilder;
use crate::predicate::Predicate;
use crate::util::*;

use boolean_expression::Expr::*;

use std::net::Ipv4Addr;
use libc::ETH_P_IP;

pub fn ether_type<B: ConditionBuilder>(ether_type: u16) -> B::Condition {
    B::offset_equals_u16(OFFSET_ETHER_TYPE.into(), ether_type)
}

pub fn ip_dst<B: ConditionBuilder>(ip: Ipv4Addr) -> Predicate<B::Condition> {
    Predicate::from(And(
        Box::new(Terminal(ether_type::<B>(ETH_P_IP as _))),
        Box::new(Terminal(B::offset_equals_u32(
            OFFSET_IP_DST.into(),
            ip.into(),
        ))),
    ))
}

pub fn ip_src<B: ConditionBuilder>(ip: Ipv4Addr) -> Predicate<B::Condition> {
    Predicate::from(And(
        Box::new(Terminal(ether_type::<B>(ETH_P_IP as _))),
        Box::new(Terminal(B::offset_equals_u32(
            OFFSET_IP_SRC.into(),
            ip.into(),
        ))),
    ))
}

pub fn ip_host<B: ConditionBuilder>(ip: Ipv4Addr) -> Predicate<B::Condition> {
    ip_src::<B>(ip) | ip_dst::<B>(ip)
}

/*
pub fn ether_dst(mac: MacAddress) -> Predicate<Condition> {
    let (i, h) = mac_to_u32_and_u16(mac);
    Predicate::from(And(
        Box::new(Terminal(offset_equals(OFFSET_ETHER_DST, Value::Word(i)))),
        Box::new(Terminal(offset_equals(
            OFFSET_ETHER_DST + size_of::<u32>() as u32,
            Value::Word(h as u32),
        ))),
    ))
}

pub fn ether_src(mac: MacAddress) -> Predicate<Condition> {
    let (i, h) = mac_to_u32_and_u16(mac);
    Predicate::from(And(
        Box::new(Terminal(offset_equals(OFFSET_ETHER_SRC, Value::Word(i)))),
        Box::new(Terminal(offset_equals(
            OFFSET_ETHER_SRC + size_of::<u32>() as u32,
            Value::Word(h as u32),
        ))),
    ))
}

pub fn ether_host(mac: MacAddress) -> Predicate<Condition> {
    ether_src(mac) | ether_dst(mac)
}


*/
