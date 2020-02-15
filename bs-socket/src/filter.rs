use crate::socket::{BasicSocket, Socket, SocketKind};
use bs_cbpf::{SocketFilter, SocketFilterProgram};
use bs_filter::{backend, backend::Backend};
use bs_system::{Result, SetSocketOption};
use cfg_if::cfg_if;
use std::convert::TryFrom;
use std::os::unix::io::RawFd;

/// A struct implementing this trait can be attached to a [`Socket`] to filter
/// received traffic.
///
/// This implementation will usualy be platform specific.
/// The methods defined by this trait  and should not be called directrly and should only be used
/// through [`Socket`]'s relevant methods.
///
/// [`Socket`]: ../../bs-socket/socket/struct.Socket.html
pub trait AttachFilter: Sized {
    /// XXX
    type Instruction: Sized;
    /// Apply the filter to the socket
    fn attach(&self, socket: RawFd) -> Result<()>;
    /// XXX
    fn from_instructions(instructions: Vec<Self::Instruction>) -> Result<Self>;
}

#[cfg(target_os = "linux")]
impl AttachFilter for SocketFilterProgram {

    type Instruction = SocketFilter;

    fn attach(&self, socket: RawFd) -> Result<()> {
        self.set(socket)
    }

    fn from_instructions(instructions: Vec<Self::Instruction>) -> Result<Self> {
        SocketFilterProgram::try_from(instructions)
    }
}

cfg_if! { if #[cfg(all(target_os = "linux", feature = "ebpf"))] {
use bs_ebpf::{SocketFilterFd, Instruction, SocketFilterBpfAttribute};

impl AttachFilter for SocketFilterFd {

    type Instruction = Instruction;

    fn attach(&self, socket: RawFd) -> Result<()> {
        self.set(socket)
    }

    fn from_instructions(instructions: Vec<Self::Instruction>) -> Result<Self> {
        SocketFilterBpfAttribute::new(instructions).load()
    }
}
}}

mod private {
    use super::*;

    pub trait PrivateSetFilter: BasicSocket {
        /// Sets a new socket filter in the socket, or replaces the existing filter if already set
        fn attach_filter(&mut self, filter: impl AttachFilter) -> Result<&mut Self> {
            filter.attach(self.os()).map(|_| self)
        }
    }

    impl<S: SocketKind> PrivateSetFilter for Socket<S> {}
}

/// Extends [`BasicSocket`](trait.BasicSocket.html) with a method to set a packet filter on the
/// socket
pub trait SetFilter: private::PrivateSetFilter {
    // TODO - all code below is linux specific...

    cfg_if! { if #[cfg(target_os = "linux")] {
    /// Flushes the socket's incoming stream and sets a new filter
    fn set_filter<C: AttachFilter<Instruction=<backend::Classic as Backend>::Instruction>, F: AttachFilter>(&mut self, filter: F) -> Result<&mut Self> {
        self.attach_filter(C::from_instructions(
            backend::Classic::contradiction(),
        )?)?
        .drain()?
        .attach_filter(filter)
    }
    }}
}

impl<S: SocketKind> SetFilter for Socket<S> {}
