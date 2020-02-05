#[cfg(test)]
mod tests;

pub mod cbpf;
//pub(crate) mod condition_builder;
//pub mod ebpf;
pub(crate) mod predicate;
//pub(crate) mod ready_made;
pub(crate) mod util;
use std::marker::PhantomData;
pub use std::io::Result;

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


/// The `backend` module holds phantom structs that
/// represent the relevant backend of BPF operation
/// (Classic / Extended). This module will be replaced
/// with an enum when const generics land in stable rust.
pub mod backend {
    use crate::cbpf;
    use crate::Instruction;
    use crate::Result;
    use crate::ApplyFilter;
    use std::fmt::Debug;
    use std::hash::Hash;

    /// Phantom struct to represent Classic BPF related
    /// functionalities.
    #[derive(Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd)]
    pub struct Classic {}

    /// Phantom struct to represent Extended BPF related
    /// functionalities.
    #[derive(Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd)]
    pub struct Extended {}

    pub trait FilterBackend {
        type SocketOption: Debug + ApplyFilter;
    }
    impl FilterBackend for Classic {
        type SocketOption = cbpf::SocketOption;
    }
    pub trait Backend: Sized + Clone + Ord + Debug + Hash + FilterBackend {
        type Comparison: Clone + Ord + Debug + Hash + From<u8>;
        type Value: Clone + Ord + Debug + Hash + From<u32>;

        fn option_level() -> i32;
        fn option_name() -> i32;
        fn initialization_sequence() -> Vec<Instruction<Self>>;
        fn return_sequence() -> (Vec<Instruction<Self>>, usize, usize);
        fn teotology() -> Vec<Instruction<Self>>;
        fn contradiction() -> Vec<Instruction<Self>>;
        fn into_socket_option(instructions: Vec<Instruction<Self>>) -> Result<Self::SocketOption>;
        fn jump(
            comparison: Self::Comparison,
            operand: Self::Value,
            jt: usize,
            jf: usize,
        ) -> Vec<Instruction<Self>>;
        fn load_u8_at(offset: u32) -> Vec<Instruction<Self>>;
        fn load_u16_at(offset: u32) -> Vec<Instruction<Self>>;
        fn load_u32_at(offset: u32) -> Vec<Instruction<Self>>;
    }

    impl Backend for Classic {
        type Comparison = cbpf::Comparison;
        type Value = cbpf::Value;

        fn option_level() -> i32 {
            cbpf::OPTION_LEVEL
        }
        fn option_name() -> i32 {
            cbpf::OPTION_NAME
        }
        fn initialization_sequence() -> Vec<Instruction<Self>> {
            cbpf::initialization_sequence()
        }
        fn return_sequence() -> (Vec<Instruction<Self>>, usize, usize) {
            cbpf::return_sequence()
        }
        fn teotology() -> Vec<Instruction<Self>> {
            cbpf::teotology()
        }
        fn contradiction() -> Vec<Instruction<Self>> {
            cbpf::contradiction()
        }
        fn into_socket_option(instructions: Vec<Instruction<Self>>) -> Result<Self::SocketOption> {
            cbpf::into_socket_option(instructions)
        }
        fn jump(
            comparison: Self::Comparison,
            operand: Self::Value,
            jt: usize,
            jf: usize,
        ) -> Vec<Instruction<Self>> {
            cbpf::jump(comparison, operand, jt, jf)
        }
        fn load_u8_at(offset: u32) -> Vec<Instruction<Self>> {
            cbpf::load_u8_at(offset)
        }
        fn load_u16_at(offset: u32) -> Vec<Instruction<Self>> {
            cbpf::load_u16_at(offset)
        }
        fn load_u32_at(offset: u32) -> Vec<Instruction<Self>> {
            cbpf::load_u32_at(offset)
        }
    }

    /*
    impl FilterBackend for Extended {
        type SocketOption = ebpf::SocketOption;
    }

    impl Backend for Extended {
        type Comparison = ebpf::Comparison;
        type Value = ebpf::Value;

        fn initialization_sequence() -> Vec<Instruction<Self>> {
            ebpf::initialization_sequence()
        }
        fn return_sequence() -> (Vec<Instruction<Self>>, usize, usize) {
            ebpf::return_sequence()
        }
        fn teotology() -> Vec<Instruction<Self>> {
            ebpf::teotology()
        }
        fn contradiction() -> Vec<Instruction<Self>> {
            ebpf::contradiction()
        }
        fn into_socket_option(instructions: Vec<Instruction<Self>>) -> Result<Self::SocketOption> {
            ebpf::into_socket_option()
        }
        fn jump(
            comparison: Self::Comparison,
            operand: Self::Value,
            jt: usize,
            jf: usize,
        ) -> Vec<Instruction<Self>> {
            cbpf::jump(comparison, operand, jt, jf)
        }
    }
    */
}
use crate::util::*;
use bpf_sys::*;
pub use backend::Backend;
pub use backend::Classic;

pub fn ether_type<K: backend::Backend>(ether_type: u16) -> Condition<K> {
    Condition::new(
        Computation::new(K::load_u16_at(OFFSET_ETHER_TYPE as _)),
        K::Comparison::from(BPF_JEQ as u8),
        K::Value::from(ether_type as u32),
    )
}

pub fn ether_type_arp<K: backend::Backend>() -> Predicate<Condition<K>> {
    Predicate::from(Terminal(ether_type(0x0806))) // TODO - undo magic
}

/*
pub fn ip_dst<B: ConditionBuilder>(ip: Ipv4Addr) -> Predicate<B::Condition> {
    Predicate::from(And(
        Box::new(Terminal(ether_type::<B>(ETH_P_IP as u16))),
        Box::new(Terminal(B::offset_equals_u32(
            OFFSET_IP_DST.into(),
            ip.into(),
        ))),
    ))
}

pub fn ip_src<B: ConditionBuilder>(ip: Ipv4Addr) -> Predicate<B::Condition> {
    Predicate::from(And(
        Box::new(Terminal(ether_type::<B>(ETH_P_IP as u16))),
        Box::new(Terminal(B::offset_equals_u32(
            OFFSET_IP_SRC.into(),
            ip.into(),
        ))),
    ))
}

pub fn ip_host<B: ConditionBuilder>(ip: Ipv4Addr) -> Predicate<B::Condition> {
    ip_src::<B>(ip) | ip_dst::<B>(ip)
}
*/
