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

// BPF_A is missing from bpf_sys
const BPF_A: u32 = 0x10;

pub const DROP: Operation = Operation {
    code: (BPF_RET | BPF_K) as _,
    jt: 0,
    jf: 0,
    k: 0,
};

pub const RETURN_A: Operation = Operation {
    code: (BPF_RET | BPF_A) as _,
    jt: 0,
    jf: 0,
    k: 0,
};

pub const fn return_imm(k: u32) -> Operation {
    Operation {
        code: (BPF_RET | BPF_K) as _,
        jt: 0,
        jf: 0,
        k,
    }
}


