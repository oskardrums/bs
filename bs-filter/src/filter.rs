use crate::backend::Backend;
use crate::AttachFilter;
use bs_system::SystemError;
use std::convert::{TryFrom, TryInto};
use std::iter::FromIterator;

/// A concrete appicable socket filter
#[derive(Debug)]
pub struct Filter<K: Backend> {
    inner: Vec<K::Instruction>,
}

impl<K: Backend> Filter<K> {
    #[doc(hidden)]
    pub fn build<A: AttachFilter + TryFrom<Vec<K::Instruction>, Error = SystemError>>(
        self,
    ) -> Result<A, SystemError> {
        self.inner.try_into()
    }
}

impl<K: Backend> FromIterator<K::Instruction> for Filter<K> {
    fn from_iter<I: IntoIterator<Item = K::Instruction>>(iter: I) -> Self {
        Self {
            inner: Vec::from_iter(iter),
        }
    }
}
