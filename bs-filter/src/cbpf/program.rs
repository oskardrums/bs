use crate::cbpf::operation::Operation;
use std::iter::FromIterator;

#[repr(C)]
#[derive(Debug)]
pub struct Program {
    len: u16,
    ops: Vec<Operation>,
}

impl Program {
    pub fn new(ops: Vec<Operation>) -> Self {
        Self {
            len: ops.len() as _,
            ops,
        }
    }
}

impl FromIterator<Operation> for Program {
    fn from_iter<I: IntoIterator<Item=Operation>>(iter: I) -> Self {
        Self::new(Vec::from_iter(iter))
    }
}
