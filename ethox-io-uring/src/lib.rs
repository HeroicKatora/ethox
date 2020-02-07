// Yes, we are not no_std but we might be one day.
// Just use the minimal dependencies.
extern crate alloc;
use core::mem;

use alloc::rc::Rc;
use alloc::collections::VecDeque;

use ethox::{layer, nic, wire};
use ethox::managed::Partial;
use io_uring::opcode::{SendMsg, RecvMsg, types::Target};

mod pool;

pub struct RawRing {
    /// The ring which we use for the network interface (or UDS, or whatever fd if you go wild).
    io_ring: io_uring::IoUring,
    /// The packet memory allocation.
    memory: Rc<pool::Pool>,
    /// The fd of our socket.
    fd: libc::c_int,
    send_queue: VecDeque<PacketData>,
    recv_queue: VecDeque<PacketData>,
}

pub struct PacketBuf {
    inner: Partial<pool::Entry>,
}

pub struct Handle {
    state: State,
}

enum State {
    Raw,
    Received,
    Unsent,
    Sending,
    Receiving,
}

struct PacketData {
    handle: Handle,
    buffer: PacketBuf,
    io_vec: libc::iovec,
    io_hdr: libc::msghdr,
    // TODO cmsg buffer for the timestamps.
}

impl RawRing {
    pub fn from_ring(io_ring: io_uring::IoUring, fd: libc::c_int) -> Self {
        // TODO: register buffers from the pool and socket fd.
        RawRing {
            io_ring,
            memory: Rc::new(pool::Pool::with_size_and_count(2048, 128)),
            fd,
            send_queue: VecDeque::with_capacity(64),
            recv_queue: VecDeque::with_capacity(64),
        }
    }

    /// Submit packet data, returning the number of submitted packets. Those submitted should not
    /// be moved before completion as the msghdr will point into of them.
    unsafe fn submit_send(&mut self, data: &mut [PacketData]) -> usize {
        let mut submission = self.io_ring.submission().available();
        let remaining = submission.capacity() - submission.len();

        let mut submitted = 0;
        for packet in data.iter_mut().take(remaining) {
            packet.io_hdr.msg_iov = &mut packet.io_vec;
            let send = SendMsg::new(Target::Fd(self.fd), &packet.io_hdr).build();
            #[allow(unused_unsafe)]
            match unsafe {
                submission.push(send)
            } {
                Ok(()) => (),
                // We might even declare this unreachable.
                Err(_) => panic!("Pushed into full queue"),
            }
            submitted += 1;
        }
        submitted
    }

    /// Submit packet data, returning the number of submitted packets. Those submitted should not
    /// be moved before completion as the msghdr will point into of them.
    unsafe fn submit_recv(&mut self, data: &mut [PacketData]) -> usize {
        let mut submission = self.io_ring.submission().available();
        let remaining = submission.capacity() - submission.len();

        let mut submitted = 0;
        for packet in data.iter_mut().take(remaining) {
            packet.io_hdr.msg_iov = &mut packet.io_vec;
            let send = RecvMsg::new(Target::Fd(self.fd), &mut packet.io_hdr).build();
            #[allow(unused_unsafe)]
            match unsafe {
                submission.push(send)
            } {
                Ok(()) => (),
                // We might even declare this unreachable.
                Err(_) => panic!("Pushed into full queue"),
            }
            submitted += 1;
        }
        submitted
    }
}

impl PacketData {
    pub fn new(buffer: pool::Entry) -> Self {
        let io_vec = pool::Entry::io_vec(&buffer);
        PacketData {
            handle: Handle { state: State::Raw },
            buffer: PacketBuf {
                inner: Partial::new(buffer),
            },
            io_vec,
            // SAFETY: this is a valid initialization for a msghdr
            io_hdr: unsafe { mem::zeroed() },
        }
    }
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
        self.inner.payload()
    }
}

impl wire::PayloadMut for PacketBuf {
    fn payload_mut(&mut self) -> &mut wire::payload {
        self.inner.payload_mut()
    }

    fn resize(&mut self, length: usize) -> Result<(), wire::PayloadError> {
        self.inner.resize(length)
    }

    fn reframe(&mut self, frame: wire::Reframe) -> Result<(), wire::PayloadError> {
        self.inner.reframe(frame)
    }
}
