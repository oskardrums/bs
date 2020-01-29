use crate::condition_builder::ConditionBuilder;

use std::net::Ipv4Addr;

pub fn ip_dst<B: ConditionBuilder>(ip: Ipv4Addr) -> Predicate<Condition> {
    Predicate::from(And(
        Box::new(Terminal(ether_type(ETH_P_IP as u16))),
        Box::new(Terminal(offset_equals(
            OFFSET_IP_DST,
            Value::Word(ip.into()),
        ))),
    ))
}

pub fn ip_src(ip: Ipv4Addr) -> Predicate<Condition> {
    Predicate::from(And(
        Box::new(Terminal(ether_type(ETH_P_IP as u16))),
        Box::new(Terminal(offset_equals(
            OFFSET_IP_SRC,
            Value::Word(ip.into()),
        ))),
    ))
}

pub fn ip_host(ip: Ipv4Addr) -> Predicate<Condition> {
    ip_src(ip) | ip_dst(ip)
}

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

pub fn ether_type(ether_type: u16) -> Condition {
    offset_equals(OFFSET_ETHER_TYPE, Value::Half(ether_type))
}
