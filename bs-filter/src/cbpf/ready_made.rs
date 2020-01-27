use eui48::MacAddress;
use std::net::Ipv4Addr;
use std::mem::{transmute, size_of};
use libc::ETH_P_IP;
use bpf_sys::*;
use crate::cbpf::computation::Computation;
use crate::cbpf::condition::Condition;
use crate::cbpf::operation::{Operation, ImmArg};
use crate::predicate::Predicate;
use boolean_expression::Expr::*;

const OFFSET_ETHER_SRC: u32 = 6;
const OFFSET_ETHER_DST: u32 = 0;
const OFFSET_ETHER_TYPE: u32 = 12;
const OFFSET_IP_SRC: u32 = 26;
const OFFSET_IP_DST: u32 = 30;

pub enum Value {
    Byte(u8),
    Half(u16),
    Word(u32),
    X,
}

pub fn offset_equals(offset: ImmArg, value: Value) -> Condition {
    match value {
        Value::Byte(b) => Condition::new(
            Computation::new(vec![Operation::new((BPF_ABS | BPF_LD | BPF_B) as _, 0, 0, offset)]),
            (BPF_JMP | BPF_JEQ | BPF_K) as _,
            b as u32,
        ),
        Value::Half(h) => Condition::new(
            Computation::new(vec![Operation::new((BPF_ABS | BPF_LD | BPF_H) as _, 0, 0, offset)]),
            (BPF_JMP | BPF_JEQ | BPF_K) as _,
            h as u32,
        ),
        Value::Word(i) => Condition::new(
            Computation::new(vec![Operation::new((BPF_ABS | BPF_LD | BPF_W) as _, 0, 0, offset)]),
            (BPF_JMP | BPF_JEQ | BPF_K) as _,
            i,
        ),
        Value::X => Condition::new(
            Computation::default(),
            (BPF_JMP | BPF_JEQ | BPF_K) as _,
            0,
        ),
    }
}

pub fn ip_dst(ip: Ipv4Addr) -> Predicate<Condition> {
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

fn mac_to_u32_and_u16(mac: MacAddress) -> (u32, u16) {
    let bytes = mac.to_array();
    unsafe {
        (
            transmute::<[u8; 4], u32>([bytes[0], bytes[1], bytes[2], bytes[3]]),
            transmute::<[u8; 2], u16>([bytes[4], bytes[5]]),
        )
    }
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
