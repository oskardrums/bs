use std::mem::{forget, size_of, transmute};
use std::net::Ipv4Addr;
use bpf_sys::*;

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


