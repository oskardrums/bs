use crate::backend::Backend;
use std::iter::FromIterator;
use bs_system::Result;

/// BPF Program for filtering packets on a socket
#[repr(C)]
#[derive(Debug)]
pub struct Program<K: Backend> {
    filter: Vec<K::Instruction>,
}

impl<K: Backend> Program<K> {
    /// Creates a new `Program` from the given instructions
    pub fn new(instructions: Vec<K::Instruction>) -> Self {
        Self { filter: instructions }
    }

    /// Creates a `SocketOption` referring to this `Program`
    pub fn build(self) -> Result<K::SocketOption> {
        K::into_socket_option(self.filter)
    }
}

impl<K: Backend> FromIterator<K::Instruction> for Program<K> {
    fn from_iter<I: IntoIterator<Item = K::Instruction>>(iter: I) -> Self {
        Self::new(Vec::from_iter(iter))
    }
}
