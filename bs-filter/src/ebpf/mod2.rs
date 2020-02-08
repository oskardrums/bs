pub(crate) mod compile;
pub(crate) mod computation;
pub(crate) mod condition;
pub(crate) mod jump_strategy;
pub(crate) mod operation;
pub(crate) mod program;

pub use compile::Compile;
pub use operation::Operation;
pub use program::Program;
use std::iter::FromIterator;

pub struct Filter {
    inner: Vec<Operation>,
}

impl Filter {
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
use condition::Condition;
use std::net::Ipv4Addr;

pub fn exit() -> Predicate<Condition> {
    ready_made::drop_all::<Condition>()
}

pub fn ip_dst(ip: Ipv4Addr) -> Predicate<Condition> {
    ready_made::ip_dst::<Condition>(ip)
}

pub fn ip_src(ip: Ipv4Addr) -> Predicate<Condition> {
    ready_made::ip_src::<Condition>(ip)
}

pub fn ip_host(ip: Ipv4Addr) -> Predicate<Condition> {
    ready_made::ip_host::<Condition>(ip)
}