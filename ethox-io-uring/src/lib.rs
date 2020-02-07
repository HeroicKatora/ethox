// Yes, we are not no_std but we might be one day.
// Just use the minimal dependencies.
extern crate alloc;
use core::{mem, slice};

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

struct SubmitInterface<'io> {
    inner: &'io mut io_uring::SubmissionQueue,
    fd: libc::c_int,
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
    pub fn from_fd(fd: libc::c_int) -> Result<Self, std::io::Error> {
        let ring = io_uring::Builder::default()
            .setup_iopoll()
            .build(32)?;
        Ok(RawRing::from_ring(ring, fd))
    }

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
}

impl SubmitInterface<'_> {
    /// Submit packet data, returning the number of submitted packets. Those submitted should not
    /// be moved before completion as the msghdr will point into of them.
    unsafe fn submit_send(&mut self, data: &mut [PacketData]) -> usize {
        let mut submission = self.inner.available();
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
        let mut submission = self.inner.available();
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

    fn rx(&mut self, max: usize, mut receiver: impl nic::Recv<Handle, PacketBuf>)
        -> layer::Result<usize>
    {
        let (_, submission, completion) = self.io_ring.split();
        let mut submit = SubmitInterface {
            inner: submission,
            fd: self.fd,
        };

        let mut count = 0;
        for entry in completion.available().take(max) {
            let idx = entry.user_data() as usize;
            let packet = &mut self.recv_queue[idx];
            packet.handle.state = State::Received;

            if entry.result() >= 0 {
                count += 1;
                receiver.receive(nic::Packet {
                    handle: &mut packet.handle,
                    payload: &mut packet.buffer,
                });
            }

            match packet.handle.state {
                State::Unsent => unimplemented!(),
                _ => unsafe {
                    submit.submit_send(slice::from_mut(packet));
                },
            }
        }

        Ok(count)
    }

    fn tx(&mut self, max: usize, mut sender: impl nic::Send<Handle, PacketBuf>)
        -> layer::Result<usize>
    {
        let (_, submission, completion) = self.io_ring.split();
        let mut submit = SubmitInterface {
            inner: submission,
            fd: self.fd,
        };

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
