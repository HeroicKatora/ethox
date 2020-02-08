// Yes, we are not no_std but we might be one day.
// Just use the minimal dependencies.
extern crate alloc;
use core::{cmp, iter, mem};

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
    io_queue: Queue,
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

/// Contains packet buffers that may be submitted to the io-uring.
struct Queue {
    /// ManuallyDrop since we can't allow the data to be dropped and freed while the kernel is
    /// still working on it. Otherwise, it might get reclaimed for another object that is then
    /// thoroughly destroyed.
    buffers: mem::ManuallyDrop<Box<[PacketData]>>,
    /// Buffers we still haven't sent but should.
    to_send: VecDeque<usize>,
    /// Buffers that were completed but not yet inspected.
    to_recv: VecDeque<usize>,
    /// Buffers that are unused.
    free: VecDeque<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Raw,
    Received,
    Unsent,
    Sending,
    Receiving,
}

struct Tag(u64);

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
            // iopoll is incompatible with recvmsg, apparently, looking through Linux source code
            // as of 5.5
            // .setup_iopoll()
            .build(32)?;
        Ok(RawRing::from_ring(ring, fd))
    }

    pub fn from_ring(io_ring: io_uring::IoUring, fd: libc::c_int) -> Self {
        // TODO: register buffers from the pool and socket fd.
        let memory = Rc::new(pool::Pool::with_size_and_count(2048, 128));
        let io_queue = Queue::with_capacity(Rc::clone(&memory), 32);
        RawRing {
            io_ring,
            memory,
            fd,
            io_queue,
        }
    }

    pub fn flush_and_reap(&mut self) -> std::io::Result<usize> {
        // Drain current completion queue.
        self.io_queue.reap(self.io_ring.completion());
        // Enter the uring.
        let result = self.io_ring.submit();
        // Reap again in case something got completed.
        self.io_queue.reap(self.io_ring.completion());
        result
    }
}

impl SubmitInterface<'_> {
    fn open_slots(&self) -> usize {
        self.inner.capacity() - self.inner.len()
    }

    /// Submit packet data, returning the number of submitted packets. Those submitted should not
    /// be moved before completion as the msghdr will point into of them.
    unsafe fn submit_send<'local>(
        &mut self,
        data: impl Iterator<Item=(&'local mut PacketData, Tag)> + ExactSizeIterator,
    ) {
        let mut submission = self.inner.available();
        let remaining = submission.capacity() - submission.len();
        assert!(data.len() <= remaining);

        for (packet, Tag(tag)) in data {
            packet.io_hdr.msg_iov = &mut packet.io_vec;
            packet.io_hdr.msg_iovlen = 1;
            let send = SendMsg::new(Target::Fd(self.fd), &packet.io_hdr)
                .build()
                .user_data(tag);
            #[allow(unused_unsafe)]
            match unsafe {
                submission.push(send)
            } {
                Ok(()) => packet.handle.state = State::Sending,
                // We might even declare this unreachable.
                Err(_) => panic!("Pushed into full queue"),
            }
        }
    }

    /// Submit packet data, returning the number of submitted packets. Those submitted should not
    /// be moved before completion as the msghdr will point into of them.
    unsafe fn submit_recv<'local>(
        &mut self,
        data: impl Iterator<Item=(&'local mut PacketData, Tag)> + ExactSizeIterator,
    ) {
        let mut submission = self.inner.available();
        let remaining = submission.capacity() - submission.len();
        assert!(data.len() <= remaining);

        for (packet, Tag(tag)) in data {
            packet.io_hdr.msg_iov = &mut packet.io_vec;
            packet.io_hdr.msg_iovlen = 1;
            let send = RecvMsg::new(Target::Fd(self.fd), &mut packet.io_hdr)
                // TODO: investigate IORING_OP_ASYNC_CANCEL and timeout cancel.
                .flags(libc::MSG_DONTWAIT as u32)
                .build()
                .user_data(tag);
            #[allow(unused_unsafe)]
            match unsafe {
                submission.push(send)
            } {
                Ok(()) => packet.handle.state = State::Receiving,
                // We might even declare this unreachable.
                Err(_) => panic!("Pushed into full queue"),
            }
        }
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

impl SubmitInterface<'_> {
    fn borrow(&mut self) -> SubmitInterface<'_> {
        SubmitInterface { fd: self.fd, inner: self.inner }
    }
}

impl Drop for RawRing {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
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
        let (submitter, submission, completion) = self.io_ring.split();
        let mut submit = SubmitInterface {
            inner: submission,
            fd: self.fd,
        };

        self.io_queue.fill(submit.borrow());
        submitter.submit().map_err(|_| layer::Error::Illegal)?;
        self.io_queue.reap(completion);

        let mut count = 0;

        for _ in 0..max {
            let idx = match self.io_queue.pop_recv() {
                Some(idx) => idx,
                None => break,
            };

            let packet = self.io_queue.get_mut(idx).unwrap();
            count += 1;
            receiver.receive(nic::Packet {
                handle: &mut packet.handle,
                payload: &mut packet.buffer,
            });

            match packet.handle.state {
                State::Unsent => {
                    self.io_queue.push_send(idx)
                },
                State::Received => {
                    packet.handle.state = State::Raw;
                    self.io_queue.push_free(idx);
                },
                other => panic!("Unexpected operation {:?} associated with retransmission buffer.", other),
            }
        }

        self.io_queue.flush(submit);
        self.io_ring.submit().map_err(|_| layer::Error::Illegal)?;

        Ok(count)
    }

    fn tx(&mut self, max: usize, mut sender: impl nic::Send<Handle, PacketBuf>)
        -> layer::Result<usize>
    {
        let (_, submission, _) = self.io_ring.split();
        let submit = SubmitInterface {
            inner: submission,
            fd: self.fd,
        };

        let mut count = 0;
        let max = cmp::min(max, submit.open_slots());

        for _ in 0..max {
            let idx = match self.io_queue.pop_free() {
                Some(idx) => idx,
                None => break,
            };

            let packet = self.io_queue.get_mut(idx).unwrap();
            packet.handle.state = State::Raw;

            sender.send(nic::Packet {
                handle: &mut packet.handle,
                payload: &mut packet.buffer,
            });

            match packet.handle.state {
                State::Unsent => {
                    self.io_queue.push_send(idx);
                    count += 1;
                },
                State::Raw => {
                    packet.handle.state = State::Raw;
                    self.io_queue.push_free(idx);
                },
                other => panic!("Unexpected operation {:?} associated with transmission buffer.", other),
            }
        }

        self.io_queue.flush(submit);
        self.io_ring.submit().map_err(|_| layer::Error::Illegal)?;

        Ok(count)
    }
}

impl Queue {
    fn with_capacity(pool: Rc<pool::Pool>, capacity: usize) -> Self {
        assert_eq!(capacity as u64 as usize, capacity, "Indexing does not survive roundtrip");
        let entries = pool::Pool::spawn_entries(pool)
            .take(capacity)
            .map(PacketData::new)
            .collect::<Vec<_>>()
            .into_boxed_slice();

        Queue {
            buffers: mem::ManuallyDrop::new(entries),
            to_send: VecDeque::with_capacity(capacity),
            to_recv: VecDeque::with_capacity(capacity),
            free: (0..capacity).collect(),
        }
    }

    fn get_mut(&mut self, idx: usize) -> Option<&mut PacketData> {
        self.buffers.get_mut(idx)
    }

    fn push_send(&mut self, idx: usize) {
        self.to_send.push_back(idx);
    }

    fn pop_recv(&mut self) -> Option<usize> {
        self.to_recv.pop_front()
    }

    fn push_free(&mut self, idx: usize) {
        self.free.push_back(idx);
    }

    fn pop_free(&mut self) -> Option<usize> {
        self.free.pop_front()
    }

    fn fill(&mut self, mut submit: SubmitInterface) {
        let max = submit.open_slots();
        for idx in self.free.drain(..).take(max) {
            let packet = self.buffers.get_mut(idx).unwrap();
            packet.io_vec.iov_len = packet.buffer.inner.capacity();
            assert_eq!(packet.handle.state, State::Raw);
            let tag = Tag(idx as u64);
            unsafe {
                submit.submit_recv(iter::once((packet, tag)));
            }
        }
    }

    fn reap(&mut self, cq: &mut io_uring::CompletionQueue) {
        for entry in cq.available() {
            let idx = entry.user_data() as usize;
            let packet = self.get_mut(idx).unwrap();
            match packet.handle.state {
                State::Sending => {
                    packet.handle.state = State::Raw;
                    self.push_free(idx);
                    continue;
                },
                State::Receiving => (),
                other => panic!("Unexpected operation {:?} associated with completed buffer.", other),
            }

            packet.handle.state = State::Received;
            if entry.result() >= 0 {
                packet.buffer.inner.set_len_unchecked(entry.result() as usize);
                self.to_recv.push_back(idx);
            } else {
                // Unhandled error.
            }
        }
    }

    fn flush(&mut self, mut submit: SubmitInterface) {
        let max = submit.open_slots();
        for idx in self.to_send.drain(..).take(max) {
            let packet = self.buffers.get_mut(idx).unwrap();
            assert_eq!(packet.handle.state, State::Unsent);
            packet.io_vec.iov_len = packet.buffer.inner.len();
            let tag = Tag(idx as u64);
            unsafe {
                submit.submit_send(iter::once((packet, tag)));
            }
        }
    }
}

impl nic::Handle for Handle {
    fn queue(&mut self) -> Result<(), layer::Error> {
        self.state = State::Unsent;
        Ok(())
    }

    fn info(&self) -> &dyn nic::Info {
        unimplemented!()
    }
}

impl wire::Payload for PacketBuf {
    fn payload(&self) -> &wire::payload {
        <Partial<_> as wire::Payload>::payload(&self.inner)
    }
}

impl wire::PayloadMut for PacketBuf {
    fn payload_mut(&mut self) -> &mut wire::payload {
        <Partial<_> as wire::PayloadMut>::payload_mut(&mut self.inner)
    }

    fn resize(&mut self, length: usize) -> Result<(), wire::PayloadError> {
        <Partial<_> as wire::PayloadMut>::resize(&mut self.inner, length)
    }

    fn reframe(&mut self, frame: wire::Reframe) -> Result<(), wire::PayloadError> {
        <Partial<_> as wire::PayloadMut>::reframe(&mut self.inner, frame)
    }
}

