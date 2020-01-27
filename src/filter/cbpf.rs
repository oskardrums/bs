use std::mem::{forget, size_of, transmute};
use std::net::Ipv4Addr;
use bpf_sys::*;

pub const BPF_LD: u16 = 0x00;
pub const BPF_LDX: u16 = 0x01;
pub const BPF_ST: u16 = 0x02;
pub const BPF_STX: u16 = 0x03;
pub const BPF_ALU: u16 = 0x04;
pub const BPF_JMP: u16 = 0x05;
pub const BPF_RET: u16 = 0x06;
pub const BPF_MISC: u16 = 0x07;
pub const BPF_W: u16 = 0x00;
pub const BPF_H: u16 = 0x08;
pub const BPF_B: u16 = 0x10;
pub const BPF_IMM: u16 = 0x00;
pub const BPF_ABS: u16 = 0x20;
pub const BPF_IND: u16 = 0x40;
pub const BPF_MEM: u16 = 0x60;
pub const BPF_LEN: u16 = 0x80;
pub const BPF_MSH: u16 = 0xa0;
pub const BPF_ADD: u16 = 0x00;
pub const BPF_SUB: u16 = 0x10;
pub const BPF_MUL: u16 = 0x20;
pub const BPF_DIV: u16 = 0x30;
pub const BPF_OR: u16 = 0x40;
pub const BPF_AND: u16 = 0x50;
pub const BPF_LSH: u16 = 0x60;
pub const BPF_RSH: u16 = 0x70;
pub const BPF_NEG: u16 = 0x80;
pub const BPF_MOD: u16 = 0x90;
pub const BPF_XOR: u16 = 0xa0;
pub const BPF_JA: u16 = 0x00;
pub const BPF_JEQ: u16 = 0x10;
pub const BPF_JGT: u16 = 0x20;
pub const BPF_JGE: u16 = 0x30;
pub const BPF_JSET: u16 = 0x40;
pub const BPF_K: u16 = 0x00;
pub const BPF_X: u16 = 0x08;

#[repr(C)]
#[derive(Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd)]
pub struct Op {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

impl Op {
    pub fn new(code: u16, jt: u8, jf: u8, k: u32) -> Op {
        Op { code, jt, jf, k }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct Prog {
    len: u16,
    filter: *mut Op,
}

impl Prog {
    pub fn new(ops: Vec<Op>) -> Prog {
        let mut ops = ops.into_boxed_slice();
        let len = ops.len();
        let ptr = ops.as_mut_ptr();

        forget(ops);

        Prog {
            len: len as _,
            filter: ptr,
        }
    }
}

impl Drop for Prog {
    fn drop(&mut self) {
        unsafe {
            let len = self.len as usize;
            let ptr = self.filter;
            Vec::from_raw_parts(ptr, len, len);
        }
    }
}

#[derive(Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd, Default)]
pub struct Computation {
    ops: Vec<Op>,
}

impl Computation {
    pub fn new(ops: Vec<Op>) -> Computation {
        Self { ops }
    }

    pub fn build(self) -> Vec<Op> {
        self.ops
    }
}

#[derive(Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd)]
pub struct Condition {
    computation: Computation,
    return_instruction: u16,
    return_argument: u32,
}

impl Condition {
    pub fn new(computation: Computation, return_instruction: u16, return_argument: u32) -> Self {
        Self {
            computation,
            return_instruction,
            return_argument,
        }
    }

    pub fn computation(self) -> Computation {
        self.computation
    }

    pub fn return_argument(&self) -> u32 {
        self.return_argument
    }

    pub fn return_instruction(&self) -> u16 {
        self.return_instruction
    }

    pub fn build(self, jt: usize, jf: usize) -> Vec<Op> {
        let mut res = {
            if jt < u8::max_value() as usize && jf < u8::max_value() as usize {
                vec![Op::new(
                    self.return_instruction(),
                    jt as u8,
                    jf as u8,
                    self.return_argument(),
                )]
            } else if jt < u8::max_value() as usize && jf >= u8::max_value() as usize {
                vec![
                    Op::new(BPF_JMP | BPF_K, 0, 0, jf as u32),
                    Op::new(
                        self.return_instruction(),
                        jt as u8 + 1,
                        0,
                        self.return_argument(),
                    ),
                ]
            } else if jt >= u8::max_value() as usize && jf < u8::max_value() as usize {
                vec![
                    Op::new(BPF_JMP | BPF_K, 0, 0, jt as u32),
                    Op::new(
                        self.return_instruction(),
                        0,
                        jf as u8 + 1,
                        self.return_argument(),
                    ),
                ]
            } else if jt >= u8::max_value() as usize && jf >= u8::max_value() as usize {
                vec![
                    Op::new(BPF_JMP | BPF_K, 0, 0, jf as u32),
                    Op::new(BPF_JMP | BPF_K, 0, 0, jt as u32),
                    Op::new(self.return_instruction(), 0, 1, self.return_argument()),
                ]
            } else {
                unreachable!();
            }
        };
        res.extend(self.computation.build());
        return res;
    }
}

pub enum ReturnStrategy {
    Truncate(u32),
    Calculate(Computation),
}

const OP_DROP_PACKET: Op = Op {
    code: BPF_RET | BPF_K,
    jt: 0,
    jf: 0,
    k: 0,
};

const fn op_return_k(k: u32) -> Op {
    Op {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k,
    }
}

impl ReturnStrategy {
    pub fn build(self) -> Vec<Op> {
        match self {
            Self::Truncate(u) => vec![OP_DROP_PACKET, op_return_k(u)],
            Self::Calculate(computation) => computation.build(),
        }
    }
}

pub trait Compile
where
    Self: Sized,
{
    fn compile_with_return_strategy(self, return_strategy: ReturnStrategy) -> Prog;

    fn compile(self) -> Prog {
        self.compile_with_return_strategy(ReturnStrategy::Truncate(u16::max_value() as u32))
    }
}

use crate::filter::predicate::Predicate;
use crate::filter::predicate::{And, Const, Not, Or, Terminal};

fn walk(predicate: Predicate<Condition>, jt: usize, jf: usize) -> Vec<Op> {
    match predicate.into_inner() {
        Terminal(condition) => condition.build(jt, jf),
        Not(e) => walk(Predicate::from(*e), jf, jt),
        And(a, b) => {
            let mut res = walk(Predicate::from(*b), jt, jf);
            res.extend(walk(Predicate::from(*a), 0, jf + res.len()));
            res
        }
        Or(a, b) => {
            let mut res = walk(Predicate::from(*b), jt, jf);
            res.extend(walk(Predicate::from(*a), jt + res.len(), 0));
            res
        }
        Const(boolean) => {
            if boolean {
                vec![op_return_k(std::u32::MAX)]
            } else {
                vec![OP_DROP_PACKET]
            }
        }
    }
}

impl Compile for Predicate<Condition> {
    // TODO - use the given offsets to adjust computations along compilation
    fn compile_with_return_strategy(mut self, return_strategy: ReturnStrategy) -> Prog {
        self = Predicate::from(self.into_inner().simplify_via_laws());
        let mut instructions = return_strategy.build();

        instructions.extend(walk(self, 0, instructions.len() - 1));

        instructions.reverse();

        println!("instructions: {:?}", instructions);
        Prog::new(instructions)
    }
}

use eui48::MacAddress;
use libc::ETH_P_IP;
const OFFSET_ETHER_SRC: u32 = 6;
const OFFSET_ETHER_DST: u32 = 0;
const OFFSET_ETHER_TYPE: u32 = 12;
const OFFSET_IP_SRC: u32 = 26;
const OFFSET_IP_DST: u32 = 30;

enum Value {
    Byte(u8),
    Half(u16),
    Word(u32),
    XByte(u8),
    XHalf(u16),
    XWord(u32),
    // TODO - support mem (M[k])
}

fn offset_equals(offset: u32, value: Value) -> Condition {
    match value {
        Value::Byte(b) => Condition::new(
            Computation::new(vec![Op::new(BPF_ABS | BPF_LD | BPF_B, 0, 0, offset)]),
            BPF_JMP | BPF_JEQ | BPF_K,
            b as u32,
        ),
        Value::Half(h) => Condition::new(
            Computation::new(vec![Op::new(BPF_ABS | BPF_LD | BPF_H, 0, 0, offset)]),
            BPF_JMP | BPF_JEQ | BPF_K,
            h as u32,
        ),
        Value::Word(i) => Condition::new(
            Computation::new(vec![Op::new(BPF_ABS | BPF_LD | BPF_W, 0, 0, offset)]),
            BPF_JMP | BPF_JEQ | BPF_K,
            i,
        ),
        Value::XByte(b) => Condition::new(
            Computation::new(vec![Op::new(BPF_ABS | BPF_LD | BPF_B, 0, 0, offset)]),
            BPF_JMP | BPF_JEQ | BPF_X,
            b as u32,
        ),
        Value::XHalf(h) => Condition::new(
            Computation::new(vec![Op::new(BPF_ABS | BPF_LD | BPF_H, 0, 0, offset)]),
            BPF_JMP | BPF_JEQ | BPF_X,
            h as u32,
        ),
        Value::XWord(i) => Condition::new(
            Computation::new(vec![Op::new(BPF_ABS | BPF_LD | BPF_W, 0, 0, offset)]),
            BPF_JMP | BPF_JEQ | BPF_X,
            i,
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

pub fn drop_all() -> Prog {
    Prog::new(vec![OP_DROP_PACKET])
}
