pub(crate) mod compile;
pub(crate) mod computation;
pub(crate) mod condition;
pub(crate) mod operation;
pub(crate) mod program;
pub(crate) mod return_strategy;

pub use compile::Compile;
use condition::Condition;
pub use operation::{Operation, DROP};
pub use program::Program;
pub use return_strategy::ReturnStrategy;
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
    fn from_iter<I: IntoIterator<Item = Operation>>(iter: I) -> Self {
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

use crate::predicate::Predicate;
use crate::ready_made;
use std::net::Ipv4Addr;

pub fn ip_dst(ip: Ipv4Addr) -> Predicate<Condition> {
    ready_made::ip_dst::<Condition>(ip)
}

pub fn ip_src(ip: Ipv4Addr) -> Predicate<Condition> {
    ready_made::ip_src::<Condition>(ip)
}

pub fn ip_host(ip: Ipv4Addr) -> Predicate<Condition> {
    ready_made::ip_host::<Condition>(ip)
}

#[derive(Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd)]
pub enum Comparison {
    Equal = 0x10,
    GreaterThan = 0x20,
    GreaterEqual = 0x30,
    AndMask = 0x40,
}

pub type Value = u32;

use crate::backend::Classic as Kind;
use crate::Instruction;
use crate::SocketOption;
use crate::Result;
use operation::{LOAD_LENGTH, RETURN_A};
pub fn initialization_sequence() -> Vec<Instruction<Kind>> {
    Default::default()
}
pub fn return_sequence() -> (Vec<Instruction<Kind>>, usize, usize) {
    (vec![RETURN_A, LOAD_LENGTH, DROP], 1, 2)
}
pub fn teotology() -> Vec<Instruction<Kind>> {
    vec![RETURN_A, LOAD_LENGTH]
}
pub fn contradiction() -> Vec<Instruction<Kind>> {
    vec![DROP]
}
pub fn into_socket_option(instructions: Vec<Instruction<Kind>>) -> Result<SocketOption<Kind>> {
    Ok(SocketOption {
        len: 10, // TODO - undo magic
        value: instructions // TODO - this wrong, should be sock_fprog
    })
}
pub fn jump(
    comparison: Comparison,
    operand: Value,
    jt: usize,
    jf: usize,
) -> Vec<Instruction<Kind>> {
    vec![jump(comparison, operand, jt, jf)]
}
