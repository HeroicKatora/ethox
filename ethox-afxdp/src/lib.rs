#![no_std]
extern crate alloc;

use afxdp::socket::{Socket, SocketRx, SocketTx};
use afxdp::umem::{UmemCompletionQueue, UmemFillQueue};
use afxdp::PENDING_LEN;
use afxdp::{buf_mmap::BufMmap, buf_pool_vec::BufPoolVec};
use alloc::boxed::Box;

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

    // the temporary pool of mapped buffers received.
    pending_rx: ArrayDeque<[BufMmap<'static, BufTag>; PENDING_LEN], Wrapping>,
    // the temporary pool of mapped buffers to fill.
    pending_fx: ArrayDeque<[BufMmap<'static, BufTag>; PENDING_LEN], Wrapping>,
    // the temporary pool of mapped buffers to transmit.
    pending_tx: ArrayDeque<[BufMmap<'static, BufTag>; PENDING_LEN], Wrapping>,
    // A buffer of handles we use temporarily to communicate with the sender and receiver.
    handles: Box<[Handle]>,
}

#[repr(transparent)]
pub struct Buffer(BufMmap<'static, BufTag>);

pub struct Handle {}

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
            .pending_rx
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
        let count = match self.rx.try_recv(&mut self.pending_rx, max, BufTag) {
            Ok(count) => count,
            Err(afxdp::socket::SocketError::Failed) => return Err(ethox::layer::Error::Exhausted),
        };

        let packets = self
            .pending_rx
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
