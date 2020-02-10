use crate::backend::Backend;
use crate::program::Program;
use std::iter::FromIterator;
use bs_system::Result;

/// A concrete appicable socket filter
#[derive(Debug)]
pub struct Filter<K: Backend> {
    inner: Vec<K::Instruction>,
}

impl<K: Backend> Filter<K> {
    /// Transform the `Filter` into a `SocketOption` settable on a `Socket`
    pub fn build(self) -> Result<K::SocketOption> {
        let prog: Program<K> = self.into(); 
        prog.build()
    }
}

impl<K: Backend> FromIterator<K::Instruction> for Filter<K> {
    fn from_iter<I: IntoIterator<Item = K::Instruction>>(iter: I) -> Self {
        Self {
            inner: Vec::from_iter(iter),
        }
    }
}

impl<K: Backend> IntoIterator for Filter<K> {
    type Item = K::Instruction;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl<K: Backend> Into<Program<K>> for Filter<K> {
    fn into(self) -> Program<K> {
        Program::from_iter(self.into_iter())
    }
}
