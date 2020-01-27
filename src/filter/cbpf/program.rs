use crate::filter::cbpf::operation::CBPFOperation;

#[repr(C)]
#[derive(Debug)]
pub(crate) struct Prog<'a> {
    len: u16,
    ops: &'a mut [CBPFOperation],
}

impl CBPFProgram<'a> {
    pub fn new(ops: &'a mut [CBPFProgram]) -> Self {
        Prog {
            len: ops.len() as _,
            ops,
        }
    }
}
