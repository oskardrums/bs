pub(crate) mod operation;
pub(crate) mod computation;
pub(crate) mod jump_strategy;
pub(crate) mod condition;
/*
pub(crate) mod program;
pub(crate) mod return_strategy;
pub(crate) mod compile;

pub use compile::Compile;
pub use return_strategy::ReturnStrategy;
pub use ready_made::*;
pub use operation::{Operation, DROP};
pub use program::Program;
use std::iter::FromIterator;

pub struct Filter {
    inner: Vec<Operation>,
}

impl Filter {
    pub fn drop_all() -> Self {
        Self { inner: vec![DROP] }
    }
    pub fn into_inner(self) -> Vec<Operation> {
        self.inner
    }
}

impl FromIterator<Operation> for Filter {
    fn from_iter<I: IntoIterator<Item=Operation>>(iter: I) -> Self {
        Self {
            inner: Vec::from_iter(iter),
        }
    }
}

impl IntoIterator for Filter {
    type Item = Operation;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl Into<Program> for Filter {
    fn into(self) -> Program {
        Program::new(self.into_inner())
    }
}
*/
