pub(crate) type CBPFCode = u16;
pub(crate) type CBPFJumpArg = u8;
pub(crate) type CBPFImmArg = u32;

#[repr(C)]
#[derive(Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd)]
pub(crate) struct CBPFOperation {
    code: CBPFCode,
    jt: CBPFJumpArg,
    jf: CBPFJumpArg,
    k: CBPFImmArg,
}

impl CBPFOperation {
    pub const fn new(code: CBPFCode, jt: CBPFJumpArg, jf: CBPFJumpArg, k: CBPFImmArg) -> Self {
        Op { code, jt, jf, k }
    }
}


