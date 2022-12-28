#![no_std]
extern crate alloc;

use afxdp::socket::{Socket, SocketRx, SocketTx};
use afxdp::umem::{UmemCompletionQueue, UmemFillQueue, UmemError};
use afxdp::PENDING_LEN;
use afxdp::{buf_mmap::BufMmap, buf_pool_vec::BufPoolVec};
use alloc::{boxed::Box, vec::Vec};

use arraydeque::{ArrayDeque, Wrapping};

use ethox::nic::Device;
use ethox::wire::{payload, Payload, PayloadMut};

#[derive(Default, Clone, Copy)]
pub struct BufTag;

pub struct AfXdp {
    rx: SocketRx<'static, BufTag>,
    tx: SocketTx<'static, BufTag>,
    sock: Socket<'static, BufTag>,

    link_fq: UmemFillQueue<'static, BufTag>,
    link_cq: UmemCompletionQueue<'static, BufTag>,

    /// free buffers with no assigned use.
    free: Vec<BufMmap<'static, BufTag>>,
    /// the temporary pool of mapped buffers received.
    queue_rx: ArrayDeque<[BufMmap<'static, BufTag>; PENDING_LEN], Wrapping>,
    /// the temporary pool of mapped buffers ready to add to fill queue.
    pending_fx: Vec<BufMmap<'static, BufTag>>,
    /// the temporary pool of mapped buffers ready to fill with transmit data.
    queue_tx: Vec<BufMmap<'static, BufTag>>,
    /// Buffers enqueued for transmit in order.
    pending_tx: ArrayDeque<[BufMmap<'static, BufTag>; PENDING_LEN], Wrapping>,

    // A buffer of handles we use temporarily to communicate with the sender and receiver.
    handles: Box<[Handle]>,

    /// Gathered statistics about socket usage, buffer usage, etc.
    stats: Box<Stats>,

    /// Number of packet buffers to reserve for receive.
    watermark_rx: usize,
    /// Number of packet buffers to reserve for transmission.
    watermark_tx: usize,
}

#[derive(Default)]
struct Stats {
}

#[repr(transparent)]
pub struct Buffer(BufMmap<'static, BufTag>);

pub struct Handle {}

/// Buffer management operations.
///
/// All operations should ensure our local liveness properties:
/// * Assuming the network card will eventually transmit queued packet and put them into the
///   completion queue then:
/// * Eventually some buffers are available for the fill queue (i.e. currently inserted or in the
///   `pending_fx` buffer).
/// * Eventually a call to `tx` can enqueue at least one buffer.
///
/// This is maintained by treating rx&tx as two separate systems of buffers, with some auxiliary
/// buffers floating freely between the two. This is _not_ optimal for latency. The pending
/// transmit queues might still grow large of receive packets sparse if all floating buffers are in
/// one of the two systems (especially if multiple sockets are involved). But real-time with small
/// guarantees is better than none.
///
/// It follows that, in the current implementation, the total number of buffers should not exceed
/// `PENDING_LEN` as this many buffers could be put into any queue. Packets would need to be
/// assigned as free floating buffers otherwise, dropping any egress or ingress content they have.
/// Not incorrect, but very inconvenient.
///
/// Invariants to uphold everywhere:
/// * Number of buffers in `free`, `pending_fx`, and the fill queue is at least `watermark_rx`.
/// * Number of buffers in `free`, `pending_tx`, and the completion queue is at least `watermark_tx`.
impl AfXdp {
    /// Cleanup the receive queue.
    ///
    /// Other packets are set aside into our fill queue. Note: sending as an 'instant response' is
    /// not guaranteed! The implementation should inspect the handles in a smarter way to avoid us
    /// dropping a retransmit here.
    ///
    /// Postcondition:
    /// * `queue_rx` is empty.
    fn clean_rx(&mut self, num: usize) -> Result<(), UmemError> {
        todo!()
    }

    /// Cleanup the transmit queue according to handles.
    ///
    /// Other packets are set aside into our fill queue.
    /// * `queue_tx` is empty.
    fn enqueue_tx(&mut self, num: usize) {
        todo!()
    }

    /// Gather some free packet buffers into the fill queue.
    ///
    /// Call this eventually after buffers from the fill queue have been consumed. Never consumes
    /// too many packets to starve the transmit queue.
    fn fill_fq(&mut self) -> usize {
        todo!()
    }

    /// Gather some free packet buffers into the transmit queue.
    ///
    /// Call this eventually after buffers are accepted for transmit. Never consumes too many
    /// packets to starve the fill queue.
    fn fill_tx(&mut self) -> usize {
        todo!()
    }
}

impl Device for AfXdp {
    type Payload = Buffer;

    type Handle = Handle;

    fn personality(&self) -> ethox::nic::Personality {
        ethox::nic::Personality::baseline()
    }

    fn tx(
        &mut self,
        max: usize,
        mut sender: impl ethox::nic::Send<Self::Handle, Self::Payload>,
    ) -> ethox::layer::Result<usize> {
        let packets = self
            .queue_tx
            .iter_mut()
            .zip(&mut self.handles[..])
            .take(max)
            .map(|(payload, handle)| ethox::nic::Packet{
                handle,
                payload: unsafe { core::mem::transmute::<_, &mut Buffer>(payload) },
            });

        sender.sendv(packets);

        todo!()
    }

    fn rx(
        &mut self,
        max: usize,
        mut receiver: impl ethox::nic::Recv<Self::Handle, Self::Payload>,
    ) -> ethox::layer::Result<usize> {
        let max = self.handles.len().min(max);
        let count = match self.rx.try_recv(&mut self.queue_rx, max, BufTag) {
            Ok(count) => count,
            Err(afxdp::socket::SocketError::Failed) => return Err(ethox::layer::Error::Exhausted),
        };

        let packets = self
            .queue_rx
            .iter_mut()
            .zip(&mut self.handles[..])
            .map(|(payload, handle)| ethox::nic::Packet{
                handle,
                payload: unsafe { core::mem::transmute::<_, &mut Buffer>(payload) },
            });

        receiver.receivev(packets);
        // FIXME: handle instantaneous retransmit.

        Ok(count)
    }
}

impl Payload for Buffer {
    fn payload(&self) -> &payload {
        afxdp::buf::Buf::get_data(&self.0).into()
    }
}

impl PayloadMut for Buffer {
    fn payload_mut(&mut self) -> &mut payload {
        afxdp::buf::Buf::get_data_mut(&mut self.0).into()
    }

    fn resize(&mut self, length: usize) -> Result<(), ethox::wire::PayloadError> {
        if let Ok(len) = u16::try_from(length) {
            Ok(afxdp::buf::Buf::set_len(&mut self.0, len))
        } else {
            Err(ethox::wire::PayloadError::BadSize)
        }
    }

    fn reframe(&mut self, reframe: ethox::wire::Reframe) -> Result<(), ethox::wire::PayloadError> {
        // Nothing special to do, we never overwrite data here.
        self.resize(reframe.length)
    }
}

impl ethox::nic::Handle for Handle {
    fn queue(&mut self) -> ethox::layer::Result<()> {
        todo!()
    }

    fn info(&self) -> &dyn ethox::nic::Info {
        todo!()
    }
}
