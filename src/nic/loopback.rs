use crate::managed::Slice;

use super::{Personality, Recv, Send, Result};

pub struct Loopback<'r> {
    buffer: Slice<'r, u8>,
    mtu: usize,
    next_recv: usize,
    sent: usize,
}

pub struct RecvPacket<'a>(RecvHandle, Slice<'a, u8>);

pub struct SendPacket<'a>(SendHandle, Slice<'a, u8>);

pub struct RecvHandle;

pub struct SendHandle(bool);

struct AckRecv<'a>(&'a mut usize, usize, &'a mut usize);

struct AckSend<'a>(&'a mut usize);

impl<'r> Loopback<'r> {
    /// Create a loopback device with mtu.
    ///
    /// It will divide the packet buffer into chunks of the provided mtu and keep track of free and
    /// used buffers
    pub fn new<P>(
        packet_buffer: P,
        mtu: usize,
    ) -> Self
        where P: Into<Slice<'r, u8>>,
    {
        Loopback {
            buffer: packet_buffer.into(),
            mtu,
            next_recv: 0,
            sent: 0,
        }
    }

    fn next_recv(&mut self) -> Option<(AckRecv, Slice<u8>)> {
        if self.sent == 0 {
            return None
        }

        let next = self.wrap_buffer(self.next_recv, 1);
        let buffer = self.buffer_at(self.next_recv);
        let buffer = &mut self.buffer[buffer];
        let ack = AckRecv(&mut self.next_recv, next, &mut self.sent);
        Some((ack, buffer.into()))
    }

    fn next_send(&mut self) -> Option<(AckSend, Slice<u8>)> {
        if self.sent == self.buffer_count() {
            return None
        }

        let send = self.wrap_buffer(self.next_recv, self.sent);
        let buffer = self.buffer_at(send);
        let buffer = &mut self.buffer[buffer];
        let ack = AckSend(&mut self.sent);
        Some((ack, buffer.into()))
    }

    fn buffer_count(&self) -> usize {
        self.buffer.len() / self.mtu
    }

    fn buffer_at(&mut self, idx: usize) -> core::ops::Range<usize> {
        let mtu = self.mtu;
        let base = mtu*idx;
        base..base+mtu
    }

    fn wrap_buffer(&self, base: usize, add: usize) -> usize {
        // FIXME: this can overflow if we are not careful.
        (base + add) % self.buffer_count()
    }
}

impl<'a, 'r> super::Device<'a> for Loopback<'r> 
    where 'r: 'a
{
    type Send = SendPacket<'a>;
    type Recv = RecvPacket<'a>;

    fn personality(&self) -> Personality {
        Personality::baseline()
    }

    fn tx<R: Send<'a, Self::Send>>(&'a mut self, max: usize, mut sender: R) -> Result<usize> {
        if max == 0 {
            return Ok(0)
        }

        let (ack, packet) = match self.next_send() {
            None => return Ok(0),
            Some(packet) => packet,
        };

        let mut packet = SendPacket(SendHandle(false), packet);
        sender.send(&mut packet);
        let sent = if packet.0.sent() {
            ack.ack();
            1
        } else {
            0
        };
        Ok(sent)
    }

    fn rx<R: Recv<'a, Self::Recv>>(&'a mut self, max: usize, mut receptor: R) -> Result<usize> {
        if max == 0 {
            return Ok(0)
        }

        let (ack, packet) = match self.next_recv() {
            None => return Ok(0),
            Some(packet) => packet,
        };

        let mut packet = RecvPacket(RecvHandle, packet);
        receptor.receive(&mut packet);
        ack.ack();
        Ok(1)
    }
}

impl<'a, 'p> super::Packet<'a> for RecvPacket<'p> where 'a: 'p {
    type Handle = RecvHandle;
    type Payload = [u8];

    fn separate(&mut self) -> (&mut Self::Handle, &mut Self::Payload) {
        (&mut self.0, self.1.as_mut_slice())
    }
}

impl<'a, 'p> super::Packet<'a> for SendPacket<'p> where 'a: 'p {
    type Handle = SendHandle;
    type Payload = [u8];

    fn separate(&mut self) -> (&mut Self::Handle, &mut Self::Payload) {
        (&mut self.0, self.1.as_mut_slice())
    }
}

impl SendHandle {
    fn send(&mut self) {
        self.0 = true;
    }

    fn sent(&self) -> bool {
        self.0
    }
}

impl AckRecv<'_> {
    fn ack(self) {
        *self.0 = self.1;
        *self.2 -= 1;
    }
}

impl AckSend<'_> {
    fn ack(self) {
        *self.0 += 1;
    }
}

impl super::Handle for RecvHandle {
    fn queue(&mut self) -> super::Result<()> {
        Err(super::Error::Illegal)
    }
}

impl super::Handle for SendHandle {
    fn queue(&mut self) -> super::Result<()> {
        Ok(self.send())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nic::{Device as _};

    #[test]
    fn simple_loopback() {
        let buffer = vec![0; 1204];
        let mut loopback = Loopback::new(buffer, 256);
        let length_io = crate::nic::tests::LengthIo;
        assert_eq!(loopback.tx(1, length_io), Ok(1));
        assert_eq!(loopback.rx(1, length_io), Ok(1));
    }
}
