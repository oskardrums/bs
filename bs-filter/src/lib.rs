pub mod cbpf;
//pub mod ebpf;
pub(crate) mod predicate;
pub(crate) mod util;
pub(crate) mod backend;
pub(crate) mod idiom;

// currently our "custom" Result type is std::io::Result
pub use std::io::Result;

// TODO - I hate PhantomData, we should change 
// Instruction to be an associated type of FilterBackend / Backend
// this will also be alot more flexibe due to not restricting the 
// inner structure of the Instruction struct
use std::marker::PhantomData;

#[repr(C)]
#[derive(Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd, Default)]
pub struct Instruction<K: backend::FilterBackend> {
    bytes: [u8; 8],
    phantom: PhantomData<K>,
}

#[derive(Debug)]
pub struct Filter<K: backend::Backend> {
    inner: Vec<Instruction<K>>,
}

use std::iter::FromIterator;
impl<K: backend::Backend> FromIterator<Instruction<K>> for Filter<K> {
    fn from_iter<I: IntoIterator<Item = Instruction<K>>>(iter: I) -> Self {
        Self {
            inner: Vec::from_iter(iter),
        }
    }
}

impl<K: backend::Backend> IntoIterator for Filter<K> {
    type Item = Instruction<K>;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl<K: backend::Backend> Into<Program<K>> for Filter<K> {
    fn into(self) -> Program<K> {
        Program::from_iter(self.into_iter())
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct Program<K: backend::Backend> {
    filter: Vec<Instruction<K>>,
}

impl<K: backend::Backend> Program<K> {
    pub fn new(ops: Vec<Instruction<K>>) -> Self {
        Self { filter: ops }
    }

    pub fn build(self) -> Result<K::SocketOption> {
        K::into_socket_option(self.filter)
    }
}

impl<K: backend::Backend> FromIterator<Instruction<K>> for Program<K> {
    fn from_iter<I: IntoIterator<Item = Instruction<K>>>(iter: I) -> Self {
        Self::new(Vec::from_iter(iter))
    }
}

#[derive(Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd, Default)]
pub struct Computation<K: backend::Backend> {
    instructions: Vec<Instruction<K>>,
}

impl<K: backend::Backend> Computation<K> {
    pub fn new(instructions: Vec<Instruction<K>>) -> Self {
        Self { instructions }
    }

    pub fn build(self) -> Vec<Instruction<K>> {
        self.instructions
    }
}

#[derive(Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd)]
pub struct Condition<K: backend::Backend> {
    computation: Computation<K>,
    comparison: K::Comparison,
    operand: K::Value,
}

impl<K: backend::Backend> Condition<K> {
    pub fn new(computation: Computation<K>, comparison: K::Comparison, operand: K::Value) -> Self {
        Self {
            computation,
            comparison,
            operand,
        }
    }

    pub fn computation(self) -> Computation<K> {
        self.computation
    }

    pub fn comparison(&self) -> &K::Comparison {
        &self.comparison
    }

    pub fn operand(&self) -> &K::Value {
        &self.operand
    }

    pub fn build(self, jt: usize, jf: usize) -> Vec<Instruction<K>> {
        let mut res = K::jump(self.comparison, self.operand, jt, jf);
        res.extend(self.computation.build());
        res
    }
}

use crate::predicate::Predicate;
use crate::predicate::{And, Const, Expr, Not, Or, Terminal};

pub trait Compile<K: backend::Backend>
where
    Self: Sized,
{
    fn compile(self) -> Filter<K>;

    fn into_expr(self) -> Expr<Condition<K>>;

    fn walk(self, jt: usize, jf: usize) -> Vec<Instruction<K>> {
        match self.into_expr() {
            Terminal(condition) => condition.build(jt, jf),
            Not(e) => Predicate::from(*e).walk(jf, jt),
            And(a, b) => {
                let mut res = Predicate::from(*b).walk(jt, jf);
                res.extend(Predicate::from(*a).walk(0, jf + res.len()));
                res
            }
            Or(a, b) => {
                let mut res = Predicate::from(*b).walk(jt, jf);
                res.extend(Predicate::from(*a).walk(jt + res.len(), 0));
                res
            }
            Const(boolean) => {
                if boolean {
                    K::teotology()
                } else {
                    K::contradiction()
                }
            }
        }
    }
}

use std::cmp::Ord;
use std::fmt::Debug;
use std::hash::Hash;
impl<K: backend::Backend> Compile<K> for Predicate<Condition<K>> {
    fn compile(mut self) -> Filter<K> {
        self = Predicate::from(self.into_inner().simplify_via_laws());
        let (mut instructions, jt, jf) = K::return_sequence();

        instructions.extend(self.walk(jt, jf));

        instructions.extend(K::initialization_sequence());

        instructions.reverse();
        println!("{:?}", instructions);

        Filter::from_iter(instructions)
    }

    fn into_expr(self) -> Expr<Condition<K>> {
        self.into_inner()
    }
}

use std::os::unix::io::RawFd;
pub trait ApplyFilter {
    fn apply(&mut self, fd: RawFd) -> Result<()>;
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
