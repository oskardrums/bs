use crate::backend::Backend;
use crate::filter::Filter;
use crate::Condition;
pub use boolean_expression::Expr;
pub use boolean_expression::Expr::*;
pub use boolean_expression::BDD;
use bs_system::Result;
use std::cmp::Ord;
use std::fmt::Debug;
use std::hash::Hash;
use std::iter::FromIterator;
use std::ops::{BitAnd, BitOr, Not};

/// A boolian logic construction of `Condition`s
/// can be extended via bitwise operation syntax (e.g. `|`, `&`)
///
/// # Example
/// ```
/// # use std::ops::{BitAnd, BitOr};
/// # use bs_filter::backend::Classic;
/// # use bs_filter::backend::Backend;
///
/// type Predicate = bs_filter::Predicate<Classic>;
///
/// fn show_or() {
///     // Predicates can be constructed with `&` to create a new And(...) Predicate
///     let true_or_false = Predicate::const_false() | Predicate::const_true();
///     assert_eq!(true_or_false.satisfiable(), true);
/// }
///
/// fn show_and() {
///     // Predicates can be constructed with `&` to create a new And(...) Predicate
///     let true_and_false = Predicate::const_false() | Predicate::const_true();
///     assert_eq!(true_and_false.satisfiable(), true);
/// }
///
/// fn show_not() {
///     let not_true = !Predicate::const_true();
///     assert_eq!(not_true.satisfiable(), false);
/// }
/// ```
#[derive(Clone, Debug, Ord, Eq, Hash, PartialEq, PartialOrd)]
pub struct Predicate<K: Backend> {
    expr: Expr<Condition<K>>,
}

impl<K: Backend> Predicate<K> {
    /// Generate a `Socket`-appropriate `Filter` implementing `self`'s logic
    pub fn compile(mut self) -> Result<Filter<K>> {
        self = Predicate::from_inner(self.into_inner().simplify_via_laws());
        let (mut instructions, jt, jf) = K::return_sequence();

        instructions.extend(self.walk(jt, jf));

        instructions.extend(K::initialization_sequence());

        instructions.reverse();
        // TODO - optimizations

        Ok(Filter::from_iter(instructions))
    }

    /// always false
    pub fn const_false() -> Self {
        Self::from_inner(Const(false))
    }

    /// always true
    pub fn const_true() -> Self {
        Self::from_inner(Const(true))
    }

    /// checks wether the predicate contains any contradictions.
    ///
    /// # Return Value
    /// * `false` means the filter doesn't accept any packets
    /// * `true` does NOT necessarily mean that the filter is passable, this is currently a
    /// best-effort and should be treated as a hint if the returned value is `true`
    pub fn satisfiable(&self) -> bool {
        let mut bdd = BDD::new();
        let func = bdd.from_expr(&self.expr);
        bdd.sat(func)
    }

    fn into_inner(self) -> Expr<Condition<K>> {
        self.expr
    }

    pub(crate) fn from_inner(expr: Expr<Condition<K>>) -> Self {
        Self { expr }
    }
    fn walk(self, jt: usize, jf: usize) -> Vec<K::Instruction> {
        match self.into_inner() {
            Terminal(condition) => condition.build(jt, jf),
            Not(e) => Predicate::from_inner(*e).walk(jf, jt),
            And(a, b) => {
                let mut res = Predicate::from_inner(*b).walk(jt, jf);
                res.extend(Predicate::from_inner(*a).walk(0, jf + res.len()));
                res
            }
            Or(a, b) => {
                let mut res = Predicate::from_inner(*b).walk(jt, jf);
                res.extend(Predicate::from_inner(*a).walk(jt + res.len(), 0));
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

impl<K: Backend> Not for Predicate<K> {
    type Output = Predicate<K>;

    fn not(self) -> Self::Output {
        Predicate {
            expr: Not(Box::new(self.into_inner())),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::backend::Classic;

    type Predicate = super::Predicate<Classic>;

    #[test]
    fn simple_and() {
        let true_and_false = Predicate::const_false() & Predicate::const_true();
        assert_eq!(true_and_false.satisfiable(), false);
    }

    #[test]
    fn simple_or() {
        let true_or_false = Predicate::const_false() | Predicate::const_true();
        assert_eq!(true_or_false.satisfiable(), true);
    }

    #[test]
    fn simple_not() {
        let not_true = !Predicate::const_true();
        assert_eq!(not_true.satisfiable(), false);
        let not_false = !Predicate::const_false();
        assert_eq!(not_false.satisfiable(), true);
    }

    #[test]
    fn complex() {
        let complex =
            !(Predicate::const_true() & Predicate::const_false()) | Predicate::const_false();
        assert_eq!(complex.satisfiable(), true);
    }
}
