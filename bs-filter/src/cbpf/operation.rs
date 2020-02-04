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

pub const CLEAR_A: Operation = Operation {
    code: (BPF_LD | BPF_IMM) as _,
    jt: 0,
    jf: 0,
    k: 0,
};

pub const LOAD_LENGTH: Operation = Operation {
    code: (BPF_LD | BPF_LEN | BPF_W) as _,
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

pub fn jump(comparison: u8, operand: u32, jt: usize, jf: usize) -> Operation {
    Operation {
        code: (BPF_JMP as u8 | comparison | BPF_K as u8) as _,
        jt: jt as _,
        jf: jf as _,
        k: operand as _,
    }
}
