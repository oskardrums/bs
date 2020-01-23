use std;
use std::mem::forget;
use std::net::Ipv4Addr;

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
        Op {
            code: code,
            jt: jt,
            jf: jf,
            k: k,
        }
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

#[derive(Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd)]
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
    // last Op must be a jump, we should force it
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
            if jt < std::u8::MAX as usize && jf < std::u8::MAX as usize {
                vec![Op::new(
                    self.return_instruction(),
                    jt as u8,
                    jf as u8,
                    self.return_argument(),
                )]
            } else if jt < std::u8::MAX as usize && jf >= std::u8::MAX as usize {
                vec![
                    Op::new(BPF_JMP | BPF_K, 0, 0, jf as u32),
                    Op::new(
                        self.return_instruction(),
                        jt as u8 + 1,
                        0,
                        self.return_argument(),
                    ),
                ]
            } else if jt >= std::u8::MAX as usize && jf < std::u8::MAX as usize {
                vec![
                    Op::new(BPF_JMP | BPF_K, 0, 0, jt as u32),
                    Op::new(
                        self.return_instruction(),
                        0,
                        jf as u8 + 1,
                        self.return_argument(),
                    ),
                ]
            } else if jt >= std::u8::MAX as usize && jf >= std::u8::MAX as usize {
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

impl IntoIterator for Computation {
    type Item = Op;
    type IntoIter = std::vec::IntoIter<Self::Item>;
    fn into_iter(self) -> Self::IntoIter {
        self.ops.into_iter()
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

const fn OP_RETURN_K(k: u32) -> Op {
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
            Self::Truncate(u) => vec![OP_DROP_PACKET, OP_RETURN_K(u)],
            Self::Calculate(computation) => computation.build(),
        }
    }
}

pub trait Compile {
    fn compile(self, ll_offset: i32, nl_offset: i32, return_strategy: ReturnStrategy) -> Prog;
}

use crate::predicate::Predicate;
use crate::predicate::{And, Const, Not, Or, Terminal};

fn walk(predicate: Predicate<Condition>, jt: usize, jf: usize) -> Vec<Op> {
    match predicate.into_inner() {
        Terminal(condition) => condition.build(jt, jf),
        Not(e) => walk(Predicate::from(*e), jf, jt),
        And(a, b) => {
            let mut res = walk(Predicate::from(*a), jt, jf);
            res.extend(walk(Predicate::from(*b), 0, jf + res.len()));
            res
        }
        Or(a, b) => {
            let mut res = walk(Predicate::from(*a), jt, jf);
            res.extend(walk(Predicate::from(*b), jt + res.len(), 0));
            res
        }
        Const(boolean) => {
            if boolean {
                vec![OP_RETURN_K(std::u32::MAX)]
            } else {
                vec![OP_DROP_PACKET]
            }
        }
    }
}

impl Compile for Predicate<Condition> {
    // TODO - use the given offsets to adjust computations along compilation
    fn compile(self, ll_offset: i32, nl_offset: i32, return_strategy: ReturnStrategy) -> Prog {
        let mut instructions = return_strategy.build();

        instructions.extend(walk(self, 0, instructions.len() - 1));

        instructions.reverse();

        Prog::new(instructions)
    }
}

use libc::ETH_P_IP;
const OFFSET_ETHER_SRC: u32 = 6;
const OFFSET_ETHER_DST: u32 = 0;
const OFFSET_ETHER_TYPE: u32 = 12;
const OFFSET_IP_SRC: u32 = 26;
const OFFSET_IP_DST: u32 = 30;

pub fn ip_dst(ip: Ipv4Addr) -> Predicate<Condition> {
    Predicate::from(And(
        Box::new(Terminal(ether_type(ETH_P_IP as u16))),
        Box::new(Terminal(Condition::new(
            Computation::new(vec![Op::new(BPF_ABS | BPF_LD | BPF_W, 0, 0, OFFSET_IP_DST)]),
            BPF_JMP | BPF_JEQ,
            ip.into(),
        ))),
    ))
}

pub fn ether_type(ether_type: u16) -> Condition {
    Condition::new(
        Computation::new(vec![Op::new(BPF_ABS | BPF_LD | BPF_H, 0, 0, OFFSET_ETHER_TYPE)]),
        BPF_JMP | BPF_JEQ,
        ether_type as u32,
    )
}

pub fn drop_all() -> Prog {
    Prog::new(vec![OP_DROP_PACKET])
}
