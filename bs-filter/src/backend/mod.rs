//! This module contains phantom structs that represent different implementations of BPF operations

use bs_system::Result;
use std::fmt::Debug;
use std::hash::Hash;

#[cfg(feature = "bs-cbpf")]
mod classic;
#[cfg(feature = "bs-cbpf")]
pub use classic::Classic;

#[cfg(feature = "bs-ebpf")]
mod extended;
#[cfg(feature = "bs-ebpf")]
pub use extended::Extended;

mod private {
    use crate::AttachFilter;

    pub trait FilterBackend {
        // TODO:
        // only linux uses setsockopt to attach filters, macOS for instance uses ioctl
        // instead. So SocketOption is not a very appropriate.
        // change SocketOption to something more cross-compatible, e.g. Attachable.
        // Also, make the into_socket_option a generic `Filter` method (with a more suitable name)
        // and get rid of `Program` entirely.
        type Output: AttachFilter;
    }
}

/// The main interface implemented BPF implementations.
/// Defines the minimal basic building blocks needed by the [`idiom`] module to create basic
/// filtering predicates that can then be composed into arbitrarily complex filter programs.
///
/// [`idiom`]: ../idiom/index.html
pub trait Backend: Sized + Clone + Ord + Debug + Hash + private::FilterBackend {
    /// Determines the kind of relation to be checked between a couple of operands on a particular
    /// jump instruction.
    type Comparison: Clone + Ord + Debug + Hash + From<u8>;
    /// The kind of operands supported by the backend for comparisons
    type Value: Clone + Ord + Debug + Hash + From<u32>;
    /// A single instruction in the program
    type Instruction: Clone + Ord + Debug + Hash + Sized;

    /// Generates a sequence of instructions that implements the initialization of a program.
    fn initialization_sequence() -> Vec<Self::Instruction>;

    /// Generates a sequence of instructions that implement the exit logic of a program.
    ///
    /// BPF programs return value is interpreted as an unsigned length to which the packet will be
    /// truncated, where 0 means "drop the packet".
    /// Unlike libpcap, `bs-cbpf` doesn't truncate the packet to an arbitrary size, but instead
    /// fetches the inspected packet total length and returns that value when packets are determined as
    /// valid by the program's logic.
    ///
    /// Exit sequences have 2 entry points corresponding to the 2 possible outcomes
    /// of the program - let the packet PASS, or DROP it.
    ///
    /// # Return Value
    /// Return value is a tuple containing a `Vec<Instruction>` representing the exit sequence, an
    /// offset in the sequence pointing to the PASS entry point, and an offset pointing
    /// to the DROP entry point.
    fn return_sequence() -> (Vec<Self::Instruction>, usize, usize);

    /// Generates a sequence of instructions that passes the entire packet.
    fn teotology() -> Vec<Self::Instruction>;

    /// Generates a sequence of instructions that drops the packet.
    fn contradiction() -> Vec<Self::Instruction>;

    /// Generates a sequence of instructions that implements a conditional jump.
    fn jump(
        comparison: Self::Comparison,
        operand: Self::Value,
        jt: usize,
        jf: usize,
    ) -> Vec<Self::Instruction>;

    /// Generates a sequence of instructions that loads one octet from a given offset in the packet.
    fn load_u8_at(offset: u32) -> Vec<Self::Instruction>;

    /// Generates a sequence of instructions that loads two octets from a given offset in the packet.
    fn load_u16_at(offset: u32) -> Vec<Self::Instruction>;

    /// Generates a sequence of instructions that loads four octets from a given offset in the packet.
    fn load_u32_at(offset: u32) -> Vec<Self::Instruction>;

    /// XXX
    fn build_attachable(instructions: Vec<Self::Instruction>) -> Result<Self::Output>;
}
