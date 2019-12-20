//! Implementation of a software loop-back device.
use crate::managed::Slice;
use crate::time::Instant;
use crate::wire::PayloadMut;

use super::common::{EnqueueFlag, PacketInfo};
use super::{Capabilities, Info, Personality, Recv, Send, Result};

/// A software loop-back device.
///
/// Maintains a ring buffer of packet buffers in flight.
pub struct Loopback<'r, C> {
    buffer: Slice<'r, C>,
    next_recv: usize,
    sent: usize,
    info: PacketInfo,
}

/// A newtype wrapper for the `nic::Handle` of `Loopback`.
///
/// This is only to ensure that future changes and additions can be done without relying on the
/// internal representation.
pub struct Handle(EnqueueFlag);

struct AckRecv<'a>(&'a mut usize, usize, &'a mut usize);

struct AckSend<'a>(&'a mut usize);

impl<'r, C: PayloadMut> Loopback<'r, C> {
    /// Create a loop-back device with mtu.
    ///
    /// It will divide the packet buffer into chunks of the provided mtu and keep track of free and
    /// used buffers
    pub fn new(buffer: Slice<'r, C>) -> Self {
        Loopback {
            buffer,
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

    fn next_recv(&mut self) -> Option<(AckRecv, &mut C)> {
        if self.sent == 0 {
            return None
        }

        let next = self.wrap_buffer(self.next_recv, 1);
        let buffer = &mut self.buffer[self.next_recv];
        let ack = AckRecv(&mut self.next_recv, next, &mut self.sent);
        Some((ack, buffer))
    }

    fn next_send(&mut self) -> Option<(AckSend, &mut C)> {
        if self.sent == self.buffer_count() {
            return None
        }

        let send = self.wrap_buffer(self.next_recv, self.sent);
        let buffer = &mut self.buffer[send];
        let ack = AckSend(&mut self.sent);
        Some((ack, buffer))
    }

    fn buffer_count(&self) -> usize {
        self.buffer.len()
    }

    fn wrap_buffer(&self, base: usize, add: usize) -> usize {
        // FIXME: this can overflow if we are not careful.
        (base + add) % self.buffer_count()
    }

    fn swap_buffers(&mut self, a: usize, b: usize) {
        if a == b {
            return;
        }

        let (a, b) = (a.min(b), a.max(b));
        let (head, tail) = self.buffer.split_at_mut(b);
        core::mem::swap(&mut head[a], &mut tail[0]);
    }
}

impl<'a, C: PayloadMut> super::Device for Loopback<'a, C> {
    type Handle = Handle;
    type Payload = C;

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

            let mut flag = Handle(EnqueueFlag::set_true(info));
            receptor.receive(super::Packet {
                handle: &mut flag,
                payload: packet,
            });
            ack.ack();

            if flag.0.was_sent() {
                // We always have some free slot now.
                let (ack, _) = self.next_send().unwrap();
                ack.ack();

                let minus_one = self.buffer_count() - 1;
                let recv_buffer = self.wrap_buffer(self.next_recv, minus_one);
                let send_buffer = self.wrap_buffer(recv_buffer, self.sent);

                self.swap_buffers(recv_buffer, send_buffer);
            }

            count += 1;
        }

        Ok(count)
    }
}

impl super::Handle for Handle {
    fn queue(&mut self) -> Result<()> {
        self.0.queue()
    }

    fn info(&self) -> &dyn Info {
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
        let mut loopback = Loopback::<Vec<u8>>::new(vec![buffer].into());
        let length_io = crate::nic::tests::LengthIo;
        assert_eq!(loopback.tx(1, length_io), Ok(1));
        assert_eq!(loopback.rx(1, length_io), Ok(1));
    }
}
