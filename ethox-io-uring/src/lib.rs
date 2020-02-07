// Yes, we are not no_std but we might be one day.
// Just use the minimal dependencies.
extern crate alloc;

use ethox::{layer, nic, wire};
use ethox::managed::Partial;

mod pool;

pub struct RawRing {
    /// The ring which we use for the network interface (or UDS, or whatever fd if you go wild).
    io_ring: io_uring::IoUring,
    /// The packet memory allocation.
    memory: pool::Pool,
    /// The network interface which we are using.
    interface: libc::c_int,
}

pub struct PacketBuf {
    inner: Partial<pool::Entry>,
}

struct Handle {
}

impl nic::Device for RawRing {
    type Payload = PacketBuf;
    type Handle = Handle;

    fn personality(&self) -> nic::Personality {
        unimplemented!()
    }

    fn rx(&mut self, max: usize, receiver: impl nic::Recv<Handle, PacketBuf>)
        -> layer::Result<usize>
    {
        unimplemented!()
    }

    fn tx(&mut self, max: usize, receiver: impl nic::Send<Handle, PacketBuf>)
        -> layer::Result<usize>
    {
        unimplemented!()
    }
}

impl nic::Handle for Handle {
    fn queue(&mut self) -> Result<(), layer::Error> {
        unimplemented!()
    }

    fn info(&self) -> &dyn nic::Info {
        unimplemented!()
    }
}

impl wire::Payload for PacketBuf {
    fn payload(&self) -> &wire::payload {
        unimplemented!()
    }
}

impl wire::PayloadMut for PacketBuf {
    fn payload_mut(&mut self) -> &mut wire::payload {
        unimplemented!()
    }

    fn resize(&mut self, length: usize) -> Result<(), wire::PayloadError> {
        unimplemented!()
    }

    fn reframe(&mut self, _: wire::Reframe) -> Result<(), wire::PayloadError> {
        unimplemented!()
    }
}
