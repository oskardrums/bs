use bs_system::Result;
use cfg_if::cfg_if;
use std::os::unix::io::RawFd;

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

cfg_if! { if #[cfg(target_os = "linux")] {
    use bs_system::SetSocketOption;
    impl<A: SetSocketOption> AttachFilter for A {
        fn attach(&self, socket: RawFd) -> Result<()> {
            self.set(socket)
        }
    }
}}
