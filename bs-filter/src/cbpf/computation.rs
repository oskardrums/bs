use crate::cbpf::operation::Operation;

#[derive(Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd, Default)]
pub struct Computation {
    ops: Vec<Operation>,
}

impl Computation {
    pub const fn new(ops: Vec<Operation>) -> Self {
        Self { ops }
    }

    pub fn build(self) -> Vec<Operation> {
        self.ops
    }
}
