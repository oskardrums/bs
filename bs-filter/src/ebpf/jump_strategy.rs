use crate::ebpf::operation::{Operation, Register, Code, Arg, Arg32, JumpOffset};
use bpf_sys::*;

#[derive(Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd)]
pub enum JumpStrategy {
   Regs(Code, Register, Register),
   Imm(Code, Register, Arg),
   Regs32(Code, Register, Register),
   Imm32(Code, Register, Arg32),
}

impl JumpStrategy {
    pub fn build(self, offset: JumpOffset) -> Vec<Operation> {
        let mut op = Operation::new();
        match self {
            Self::Regs(c, d, s) => {
                op.set_code((BPF_JMP as u8 | c | BPF_X as u8) as _);
                op.set_dst(d);
                op.set_src(s);
                op.set_offset(offset);

                vec![op]
            },
            Self::Regs32(c, d, s) => {
                op.set_code((BPF_JMP32 as u8 | c | BPF_X as u8) as _);
                op.set_dst(d);
                op.set_src(s);
                op.set_offset(offset);

                vec![op]
            },
            Self::Imm(c, d, a) => {
                op.set_code((BPF_JMP as u8 | c | BPF_K as u8) as _);
                op.set_dst(d);
                op.set_offset(offset);
                op.set_imm(a);

                vec![op]
            },
            Self::Imm32(c, d, a) => {
                op.set_code((BPF_JMP32 as u8 | c | BPF_K as u8) as _);
                op.set_dst(d);
                op.set_offset(offset);
                op.set_imm(a as _);

                vec![op]
            },
        }
    }
}
