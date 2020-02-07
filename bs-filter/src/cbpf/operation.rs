pub type Code = u16;
pub type JumpArg = u8;
pub type ImmArg = u32;

#[repr(C)]
#[derive(Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd)]
pub struct Instruction {
    code: Code,
    jt: JumpArg,
    jf: JumpArg,
    k: ImmArg,
}

use std::mem::transmute;
use std::iter::FromIterator;

impl Instruction {
    pub const fn new(code: Code, jt: JumpArg, jf: JumpArg, k: ImmArg) -> Self {
        Instruction { code, jt, jf, k }
    }
    pub fn build(self) -> Vec<u8> {
        Vec::from_iter(transmute::<Self, [u8; 8]>(self).into_iter())
    }
}
