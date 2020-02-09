//! Packet filtering for `bs`

#![deny(
    bad_style,
    const_err,
    dead_code,
    improper_ctypes,
    non_shorthand_field_patterns,
    no_mangle_generic_items,
    overflowing_literals,
    path_statements,
    patterns_in_fns_without_body,
    private_in_public,
    unconditional_recursion,
    unused,
    unused_allocation,
    unused_comparisons,
    unused_parens,
    while_true,
    missing_debug_implementations,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results,
    missing_copy_implementations
)]


pub(crate) mod cbpf;
pub(crate) mod compile;
//pub(crate) mod ebpf;
pub(crate) mod filter;
pub(crate) mod predicate;
pub(crate) mod program;
pub(crate) mod util;
#[allow(dead_code)]
pub(crate) mod consts;

pub use compile::Compile;
pub use filter::Filter;
pub use predicate::Predicate;
pub use program::Program;
pub mod backend;
pub mod idiom;

// currently our "custom" Result type is std::io::Result
pub use std::io::Result;
//pub type Result<T> = std::result::Result<T, ()>;

#[derive(Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd, Default)]
pub struct Computation<K: backend::Backend> {
    instructions: Vec<K::Instruction>,
}

impl<K: backend::Backend> Computation<K> {
    pub fn new(instructions: Vec<K::Instruction>) -> Self {
        Self { instructions }
    }

    pub fn build(self) -> Vec<K::Instruction> {
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

    pub fn build(self, jt: usize, jf: usize) -> Vec<K::Instruction> {
        let mut res = K::jump(self.comparison, self.operand, jt, jf);
        res.extend(self.computation.build());
        res
    }
}



#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
