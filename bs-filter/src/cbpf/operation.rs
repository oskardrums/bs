pub type Code = u16;
pub type JumpArg = u8;
pub type ImmArg = u32;

#[repr(C)]
#[derive(Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd)]
pub struct Operation {
    code: Code,
    jt: JumpArg,
    jf: JumpArg,
    k: ImmArg,
}

impl Operation {
    pub const fn new(code: Code, jt: JumpArg, jf: JumpArg, k: ImmArg) -> Self {
        Operation { code, jt, jf, k }
    }
}

use bpf_sys::*;

pub fn jump(comparison: u8, operand: u32, jt: usize, jf: usize) -> Operation {
    Operation {
        code: (BPF_JMP as u8 | comparison | BPF_K as u8) as _,
        jt: jt as _,
        jf: jf as _,
        k: operand as _,
    }
}
