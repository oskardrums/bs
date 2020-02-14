use crate::backend::Backend;
use bs_system::Result;
use cfg_if::cfg_if;
use std::iter::FromIterator;
use std::os::unix::io::RawFd;

/// A concrete appicable socket filter
#[derive(Debug)]
pub struct Filter<K: Backend> {
    inner: Vec<K::Instruction>,
}

impl<K: Backend> Filter<K> {
    /// Transform the `Filter` into a `SocketOption` settable on a `Socket`
    pub fn build(self) -> Result<K::Output> {
        K::build_attachable(self.inner)
    }
}

impl<K: Backend> FromIterator<K::Instruction> for Filter<K> {
    fn from_iter<I: IntoIterator<Item = K::Instruction>>(iter: I) -> Self {
        Self {
            inner: Vec::from_iter(iter),
        }
    }
}

impl<K: Backend> IntoIterator for Filter<K> {
    type Item = K::Instruction;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

/// A struct implementing this trait can be attached to a [`Socket`] to filter
/// received traffic.
///
/// This implementation will usualy be platform specific.
/// The methods defined by this trait  and should not be called directrly and should only be used
/// through [`Socket`]'s relevant methods.
///
/// [`Socket`]: ../../bs-socket/socket/struct.Socket.html
pub trait AttachFilter {
    /// Apply the filter to the socket
    fn attach(&self, socket: RawFd) -> Result<()>;
}

cfg_if! {
    if #[cfg(target_os = "linux")] {
        use bs_system::SetSocketOption;

        impl<T: SetSocketOption> AttachFilter for T {
            fn attach(&self, socket: RawFd) -> Result<()> {
                self.set(socket)
            }
        }
    }
}
