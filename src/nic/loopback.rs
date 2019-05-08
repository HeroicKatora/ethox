use crate::managed::Slice;

use super::common::EnqueueFlag;
use super::{Personality, Recv, Send, Result};

pub struct Loopback<'r> {
    buffer: Slice<'r, u8>,
    mtu: usize,
    next_recv: usize,
    sent: usize,
}

pub struct Handle<'a>(&'a mut EnqueueFlag);

pub struct Packet<'a>(Handle<'a>, &'a mut [u8]);

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

    fn next_recv(&mut self) -> Option<(AckRecv, &mut [u8])> {
        if self.sent == 0 {
            return None
        }

        let next = self.wrap_buffer(self.next_recv, 1);
        let buffer = self.buffer_at(self.next_recv);
        let buffer = &mut self.buffer[buffer];
        let ack = AckRecv(&mut self.next_recv, next, &mut self.sent);
        Some((ack, buffer))
    }

    fn next_send(&mut self) -> Option<(AckSend, &mut [u8])> {
        if self.sent == self.buffer_count() {
            return None
        }

        let send = self.wrap_buffer(self.next_recv, self.sent);
        let buffer = self.buffer_at(send);
        let buffer = &mut self.buffer[buffer];
        let ack = AckSend(&mut self.sent);
        Some((ack, buffer))
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

impl<'r> Loopback<'r> {
    pub fn personality(&self) -> Personality {
        Personality::baseline()
    }

    pub fn tx<R>(&mut self, max: usize, mut sender: R) -> Result<usize> 
        where R: for<'a> Send<'a, Packet<'a>>
    {
        let mut count = 0;

        for _ in 0..max {
            let (ack, packet) = match self.next_send() {
                None => return Ok(count),
                Some(packet) => packet,
            };

            let mut flag = EnqueueFlag::SetTrue(false);
            sender.send(Packet(Handle(&mut flag), packet));

            if flag.was_sent() {
                ack.ack();
                count += 1;
            }
        }

        Ok(count)
    }

    pub fn rx<R>(&mut self, max: usize, mut receptor: R) -> Result<usize> 
        where R: for<'a> Recv<'a, Packet<'a>>
    {
        let mut count = 0;

        for _ in 0..max {
            let (ack, packet) = match self.next_recv() {
                None => return Ok(count),
                Some(packet) => packet,
            };

            let mut flag = EnqueueFlag::NotPossible;
            receptor.receive(Packet(Handle(&mut flag), packet));
            ack.ack();

            count += 1;
        }

        Ok(count)
    }
}

impl<'a, 'p> super::Packet<'a> for Packet<'p> where 'p: 'a {
    type Handle = Handle<'p>;
    type Payload = [u8];

    fn separate(self) -> (Self::Handle, &'a mut Self::Payload) {
        (self.0, self.1)
    }
}

impl super::Handle for Handle<'_> {
    fn queue(&mut self) -> Result<()> {
        self.0.queue()
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
