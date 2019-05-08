use crate::managed::Slice;
use crate::storage::RingBuffer;

use super::{Personality, Recv, Send, Result};

pub struct Loopback<'r> {
    buffer: RingBuffer<'r, u8>,
    lengths: RingBuffer<'r, usize>,
}

pub struct RecvPacket<'a>(RecvHandle, Slice<'a, u8>);

pub struct RecvHandle;

pub struct SendHandle(bool);

impl<'r> Loopback<'r> {
    pub fn new<P, L>(
        packet_buffer: P,
        length_buffer: L,
    ) -> Self
        where P: Into<RingBuffer<'r, u8>>, L: Into<RingBuffer<'r, usize>>
    {
        Loopback {
            buffer: packet_buffer.into(),
            lengths: length_buffer.into(),
        }
    }

    fn dequeue_one(&mut self) -> Option<Slice<u8>> {
        let length = self.lengths.enqueue_one()?;
        let packet = self.buffer.dequeue_many(*length);
        Some(packet.into())
    }
}

impl<'a, 'p> super::Packet<'a> for RecvPacket<'p> where 'a: 'p {
    type Handle = RecvHandle;
    type Payload = [u8];

    fn separate(&mut self) -> (&mut Self::Handle, &mut Self::Payload) {
        (&mut self.0, self.1.as_mut_slice())
    }
}

impl<'a, 'r> super::Device<'a> for Loopback<'r> 
    where 'r: 'a
{
    type Send = RecvPacket<'a>;
    type Recv = RecvPacket<'a>;

    fn personality(&self) -> Personality {
        Personality::baseline()
    }

    fn tx<R: Send<'a, Self::Send>>(&'a mut self, max: usize, sender: R) -> Result<usize> {
        unimplemented!()
    }

    fn rx<R: Recv<'a, Self::Recv>>(&'a mut self, _: usize, mut receptor: R) -> Result<usize> {
        let packet = match self.dequeue_one() {
            None => return Ok(0),
            Some(packet) => packet,
        };
        let mut packet = RecvPacket(RecvHandle, packet);
        receptor.receive(&mut packet);
        Ok(1)
    }
}

impl super::Handle for RecvHandle {
    fn queue(&mut self) -> super::Result<()> {
        Err(super::Error::Illegal)
    }
}
