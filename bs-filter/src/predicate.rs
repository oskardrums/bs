use crate::backend::Backend;
use crate::filter::Filter;
use crate::Condition;
pub use boolean_expression::Expr;
pub use boolean_expression::Expr::*;
use std::cmp::Ord;
use std::fmt::Debug;
use std::hash::Hash;
use std::iter::FromIterator;
use std::ops::{BitAnd, BitOr};
use bs_sockopt::Result;

/// A boolian logic construction of `Condition`s
/// can be extended via bitwise operation syntax, see example below
/// ```
/// # use std::ops::{BitAnd, BitOr};
/// # use bs_filter::Predicate;
/// # use bs_filter::backend::Classic;
/// # use bs_filter::backend::Backend;
/// # use boolean_expression::Expr::*;
/// fn do_and() {
///     assert_eq!(
///         // Predicates can be constructed with `&` to create a new And(...) Predicate
///         Predicate::<Classic>::from(Const(true)) & Predicate::from(Const(false)),
///         Predicate::<Classic>::from(And(Box::new(Const(true)), Box::new(Const(false))))
///     );
/// }
/// 
/// fn do_or() {
///     assert_eq!(
///         // the same goes for `|` and Or(...)
///         Predicate::<Classic>::from(Const(true)) | Predicate::from(Const(false)),
///         Predicate::<Classic>::from(Or(Box::new(Const(true)), Box::new(Const(false))))
///     );
/// }
/// ```
#[derive(Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd)]
pub struct Predicate<K: Backend> {
    expr: Expr<Condition<K>>,
}

impl<K: Backend> Predicate<K> {
    /// Generate a `Socket`-appropriate `Filter` implementing `self`'s logic
    pub fn compile(mut self) -> Result<Filter<K>> {
        self = Predicate::from(self.into_inner().simplify_via_laws());
        let (mut instructions, jt, jf) = K::return_sequence();

        instructions.extend(self.walk(jt, jf));

        instructions.extend(K::initialization_sequence());

        instructions.reverse();

        Ok(Filter::from_iter(instructions))
    }

    fn into_inner(self) -> Expr<Condition<K>> {
        self.expr
    }

    fn walk(self, jt: usize, jf: usize) -> Vec<K::Instruction> {
        match self.into_inner() {
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

impl<K: Backend> BitAnd for Predicate<K> {
    type Output = Predicate<K>;

    fn bitand(self, rhs: Predicate<K>) -> Self::Output {
        Predicate {
            expr: And(Box::new(self.into_inner()), Box::new(rhs.into_inner())),
        }
    }
}

impl<K: Backend> BitOr for Predicate<K> {
    type Output = Predicate<K>;

    fn bitor(self, rhs: Predicate<K>) -> Self::Output {
        Predicate {
            expr: Or(Box::new(self.into_inner()), Box::new(rhs.into_inner())),
        }
    }
}

impl<K: Backend> From<Expr<Condition<K>>> for Predicate<K> {
    fn from(expr: Expr<Condition<K>>) -> Self {
        Self { expr }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::Classic;

    #[test]
    fn simple_and() {
        assert_eq!(
            Predicate::<Classic>::from(Const(true)) & Predicate::from(Const(false)),
            Predicate::<Classic>::from(And(Box::new(Const(true)), Box::new(Const(false))))
        );
    }

    #[test]
    fn simple_or() {
        assert_eq!(
            Predicate::<Classic>::from(Const(true)) | Predicate::from(Const(false)),
            Predicate::<Classic>::from(Or(Box::new(Const(true)), Box::new(Const(false))))
        );
    }
}
