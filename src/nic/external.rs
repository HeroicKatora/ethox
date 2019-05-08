//! A stub nic whose buffers come from an external source.
use core::ops::{Deref, DerefMut};
use crate::managed::Slice;
use crate::wire::Payload;

use super::{Personality, Recv, Send, Result};
use super::common::EnqueueFlag;

pub struct Handle(EnqueueFlag);

pub struct Packet<'a, P>(Handle, &'a mut P);

pub struct External<T> {
    /// Backing buffer, accessible as a slice of packet payloads.
    buffer: T,

    /// Number of received packages.
    recv: usize,

    /// Number of sent packages.
    sent: usize,

    /// The index of the split.
    split: usize,
}

impl<T> External<T> {
    /// Set the index of the last to-receive buffer.
    pub fn set_one_past_receive(&mut self, at: usize) {
        self.split = at;
    }

    /// Reset sending, resending into the first buffer.
    pub fn reset_send(&mut self) {
        self.sent = 0;
    }

    /// Reset receiving, receiving the first buffer again.
    pub fn reset_receive(&mut self) {
        self.recv = 0;
    }
}

impl<T, P> External<T> where T: Deref<Target=[P]> {
    /// A new external nic, only sending packets.
    pub fn new_send(buffer: T) -> Self {
        External {
            buffer,
            recv: 0,
            sent: 0,
            split: 0,
        }
    }

    /// A new external nic, only receiving packets.
    pub fn new_recv(buffer: T) -> Self {
        let len = buffer.len();
        External {
            buffer,
            recv: 0,
            sent: 0,
            split: len,
        }
    }

    /// Remaining number of buffers to receive.
    pub fn to_recv(&self) -> usize {
        self.buffer.len()
            .min(self.split)
            .saturating_sub(self.recv)
    }

    /// Remaining number of buffers to send.
    pub fn to_send(&self) -> usize {
        self.buffer.len()
            .saturating_sub(self.split)
            .saturating_sub(self.sent)
    }

    fn next_recv(&self) -> usize {
        self.recv
    }

    fn next_send(&self) -> usize {
        self.split + self.sent
    }
}

impl<'a, T, P> super::Device<'a> for External<T>
where
    T: Deref<Target=[P]> + DerefMut + 'a,
    P: Payload + 'a,
{
    type Send = Packet<'a, P>;
    type Recv = Packet<'a, P>;

    fn personality(&self) -> Personality {
        Personality::baseline()
    }

    fn tx<R: Send<'a, Self::Send>>(&'a mut self, max: usize, mut sender: R) -> Result<usize> {
        if max == 0 || self.to_send() == 0 {
            return Ok(0)
        }

        let next_id = self.next_send();
        let buffer = &mut self.buffer[next_id];

        let mut packet = Packet(Handle(EnqueueFlag::SetTrue(false)), buffer);
        sender.send(&mut packet);

        if packet.0 .0.was_sent() {
            self.sent += 1;
            Ok(1)
        } else {
            Ok(0)
        }
    }

    fn rx<R: Recv<'a, Self::Recv>>(&'a mut self, max: usize, mut receptor: R) -> Result<usize> {
        if max == 0 || self.to_recv() == 0 {
            return Ok(0)
        }

        let next_id = self.next_recv();
        let buffer = &mut self.buffer[next_id];

        let mut packet = Packet(Handle(EnqueueFlag::NotPossible), buffer);
        receptor.receive(&mut packet);

        self.recv += 1;
        Ok(1)
    }
}

impl<'a, 'p: 'a, P> super::Packet<'a> for Packet<'p, P>
where
    P: Payload + 'a,
{
    type Handle = Handle;
    type Payload = P;

    fn separate(&mut self) -> (&mut Self::Handle, &mut Self::Payload) {
        (&mut self.0, &mut self.1)
    }
}

impl super::Handle for Handle {
    fn queue(&mut self) -> super::Result<()> {
        self.0.queue()
    }
}
