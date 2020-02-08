use crate::backend::Backend;
use std::iter::FromIterator;

#[repr(C)]
#[derive(Debug)]
pub struct Program<K: Backend> {
    filter: Vec<K::Instruction>,
}

impl<K: Backend> Program<K> {
    pub fn new(ops: Vec<K::Instruction>) -> Self {
        Self { filter: ops }
    }

    pub fn build(&mut self) -> Option<K::SocketOption> {
        K::as_socket_option(&mut self.filter)
    }
}

impl<K: Backend> FromIterator<K::Instruction> for Program<K> {
    fn from_iter<I: IntoIterator<Item = K::Instruction>>(iter: I) -> Self {
        Self::new(Vec::from_iter(iter))
    }
}
