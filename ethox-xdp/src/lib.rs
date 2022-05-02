mod umem;

use ethox::nic::{self, Device};
use ethox::wire::payload;
use self::umem::{Umem, Rx, Tx};

pub struct Xdp {
    umem: Umem,
    rx_queue: Rx,
    tx_queue: Tx,
    buffer: PoolBuffer,
}

pub struct PoolBuffer {
}

/// The public interface to an XDP managed packet slot.
pub trait Handle: nic::Handle + 'static {
}

impl Device for Xdp {
    type Handle = dyn Handle;
    type Payload = payload;

    fn personality(&self) -> nic::Personality {
        nic::Personality::baseline()
    }

    fn tx(&mut self, max: usize, mut sender: impl nic::Send<Self::Handle, Self::Payload>)
        -> ethox::layer::Result<usize>
    {
        sender.sendv(self.tx_front().take(max));
        self.tx_queue()
    }

    fn rx(&mut self, max: usize, mut receiver: impl nic::Recv<Self::Handle, Self::Payload>)
        -> ethox::layer::Result<usize>
    {
        self.rx_queue()?;
        receiver.receivev(self.rx_front().take(max));
        self.tx_queue()
    }
}

impl Xdp {
    fn rx_queue(&mut self) -> ethox::layer::Result<usize> {
        todo!()
    }

    fn tx_queue(&mut self) -> ethox::layer::Result<usize> {
        todo!()
    }

    fn tx_front(&mut self) -> impl Iterator<Item=nic::Packet<'_, dyn Handle, payload>> {
        todo!();
        core::iter::empty()
    }

    fn rx_front(&mut self) -> impl Iterator<Item=nic::Packet<'_, dyn Handle, payload>> {
        todo!();
        core::iter::empty()
    }
}
