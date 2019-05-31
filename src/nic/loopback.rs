use crate::managed::Slice;
use crate::time::Instant;

use super::common::{EnqueueFlag, PacketInfo};
use super::{Capabilities, Info, Personality, Recv, Send, Result};

pub struct Loopback<'r> {
    buffer: Slice<'r, u8>,
    mtu: usize,
    next_recv: usize,
    sent: usize,
    info: PacketInfo,
}

pub struct Handle(EnqueueFlag);

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
            info: PacketInfo {
                timestamp: Instant::from_millis(0),
                capabilities: Capabilities::no_support(),
            },
        }
    }

    /// Update the timestamp on all future received packets.
    pub fn set_current_time(&mut self, instant: Instant) {
        self.info.timestamp = instant;
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

impl<'a> super::Device<'a> for Loopback<'a> {
    type Handle = Handle;
    type Payload = [u8];

    fn personality(&self) -> Personality {
        Personality::baseline()
    }

    fn tx(&mut self, max: usize, mut sender: impl Send<Self::Handle, Self::Payload>)
        -> Result<usize> 
    {
        let mut count = 0;
        let info = self.info;

        for _ in 0..max {
            let (ack, packet) = match self.next_send() {
                None => return Ok(count),
                Some(packet) => packet,
            };

            let mut flag = Handle(EnqueueFlag::set_true(info));
            sender.send(super::Packet {
                handle: &mut flag,
                payload: packet,
            });

            if flag.0.was_sent() {
                ack.ack();
                count += 1;
            }
        }

        Ok(count)
    }

    fn rx(&mut self, max: usize, mut receptor: impl Recv<Self::Handle, Self::Payload>)
        -> Result<usize>
    {
        let mut count = 0;
        let info = self.info;

        for _ in 0..max {
            let (ack, packet) = match self.next_recv() {
                None => return Ok(count),
                Some(packet) => packet,
            };

            let mut flag = Handle(EnqueueFlag::not_possible(info));
            receptor.receive(super::Packet {
                handle: &mut flag,
                payload: packet,
            });
            ack.ack();

            count += 1;
        }

        Ok(count)
    }
}

impl super::Handle for Handle {
    fn queue(&mut self) -> Result<()> {
        self.0.queue()
    }

    fn info(&self) -> &Info {
        self.0.info()
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
