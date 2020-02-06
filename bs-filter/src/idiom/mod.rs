pub mod ethernet;
/*
pub fn ip_dst<B: ConditionBuilder>(ip: Ipv4Addr) -> Predicate<B::Condition> {
    Predicate::from(And(
        Box::new(Terminal(ether_type::<B>(ETH_P_IP as u16))),
        Box::new(Terminal(B::offset_equals_u32(
            OFFSET_IP_DST.into(),
            ip.into(),
        ))),
    ))
}

pub fn ip_src<B: ConditionBuilder>(ip: Ipv4Addr) -> Predicate<B::Condition> {
    Predicate::from(And(
        Box::new(Terminal(ether_type::<B>(ETH_P_IP as u16))),
        Box::new(Terminal(B::offset_equals_u32(
            OFFSET_IP_SRC.into(),
            ip.into(),
        ))),
    ))
}

pub fn ip_host<B: ConditionBuilder>(ip: Ipv4Addr) -> Predicate<B::Condition> {
    ip_src::<B>(ip) | ip_dst::<B>(ip)
}
*/
