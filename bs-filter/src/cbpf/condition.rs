use crate::cbpf::computation::Computation;
use crate::cbpf::operation::{Code, ImmArg, Operation};
use crate::condition_builder::ConditionBuilder;
use bpf_sys::*;

#[derive(Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd)]
pub struct Condition {
    computation: Computation,
    return_instruction: Code,
    return_argument: ImmArg,
}

impl Condition {
    pub const fn new(
        computation: Computation,
        return_instruction: Code,
        return_argument: ImmArg,
    ) -> Self {
        Self {
            computation,
            return_instruction,
            return_argument,
        }
    }

    pub fn computation(self) -> Computation {
        self.computation
    }

    pub fn return_argument(&self) -> ImmArg {
        self.return_argument
    }

    pub fn return_instruction(&self) -> Code {
        self.return_instruction
    }

    pub fn build(self, jt: usize, jf: usize) -> Vec<Operation> {
        let mut res = {
            if jt < u8::max_value() as usize && jf < u8::max_value() as usize {
                vec![Operation::new(
                    self.return_instruction(),
                    jt as u8,
                    jf as u8,
                    self.return_argument(),
                )]
            } else if jt < u8::max_value() as usize && jf >= u8::max_value() as usize {
                vec![
                    Operation::new((BPF_JMP | BPF_K) as _, 0, 0, jf as u32),
                    Operation::new(
                        self.return_instruction(),
                        jt as u8 + 1,
                        0,
                        self.return_argument(),
                    ),
                ]
            } else if jt >= u8::max_value() as usize && jf < u8::max_value() as usize {
                vec![
                    Operation::new((BPF_JMP | BPF_K) as _, 0, 0, jt as u32),
                    Operation::new(
                        self.return_instruction(),
                        0,
                        jf as u8 + 1,
                        self.return_argument(),
                    ),
                ]
            } else if jt >= u8::max_value() as usize && jf >= u8::max_value() as usize {
                vec![
                    Operation::new((BPF_JMP | BPF_K) as _, 0, 0, jf as u32),
                    Operation::new((BPF_JMP | BPF_K) as _, 0, 0, jt as u32),
                    Operation::new(self.return_instruction(), 0, 1, self.return_argument()),
                ]
            } else {
                unreachable!();
            }
        };
        res.extend(self.computation.build());
        return res;
    }
}

pub enum Value {
    Byte(u8),
    Half(u16),
    Word(u32),
    X,
}

impl ConditionBuilder for Condition {
    type Offset = ImmArg;
    type Value = Value;
    type Condition = Self;

    fn offset_equals(offset: Self::Offset, value: Self::Value) -> Self::Condition {
        match value {
            Value::Byte(b) => Condition::new(
                Computation::new(vec![Operation::new(
                    (BPF_ABS | BPF_LD | BPF_B) as _,
                    0,
                    0,
                    offset,
                )]),
                (BPF_JMP | BPF_JEQ | BPF_K) as _,
                b as u32,
            ),
            Value::Half(h) => Condition::new(
                Computation::new(vec![Operation::new(
                    (BPF_ABS | BPF_LD | BPF_H) as _,
                    0,
                    0,
                    offset,
                )]),
                (BPF_JMP | BPF_JEQ | BPF_K) as _,
                h as u32,
            ),
            Value::Word(i) => Condition::new(
                Computation::new(vec![Operation::new(
                    (BPF_ABS | BPF_LD | BPF_W) as _,
                    0,
                    0,
                    offset,
                )]),
                (BPF_JMP | BPF_JEQ | BPF_K) as _,
                i,
            ),
            Value::X => Condition::new(Computation::default(), (BPF_JMP | BPF_JEQ | BPF_K) as _, 0),
        }
    }
}
