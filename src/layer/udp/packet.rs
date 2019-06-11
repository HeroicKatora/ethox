use core::convert::TryFrom;

use crate::nic::Info;
use crate::layer::{Error, Result, ip};
use crate::wire::{Payload, PayloadMut};
use crate::wire::{IpAddress, IpCidr, IpProtocol, UdpChecksum, UdpPacket, UdpRepr, udp_packet};

pub struct Packet<'a, P: Payload> {
    pub handle: Handle<'a>,
    pub packet: UdpPacket<ip::IpPacket<'a, P>>,
}

pub struct RawPacket<'a, P: Payload> {
    pub handle: Handle<'a>,
    pub payload: &'a mut P,
}

/// A reference to the endpoint of layers below (phy + eth + ip + udp).
///
/// This is not really useful on its own but should instead be used either within a `Packet` or a
/// `RawPacket`. Some of the methods offered there will access the non-public members of this
/// struct to fulfill their task.
pub struct Handle<'a> {
    pub(crate) inner: ip::Handle<'a>,
    // Nothing more, there is no logic here.
}

pub struct Init {
    pub src_mask: IpCidr,
    pub src_port: u16,
    pub dst_addr: IpAddress,
    pub dst_port: u16,
    pub payload: usize,
}

impl<'a> Handle<'a> {
    pub(crate) fn new(
        handle: ip::Handle<'a>,
    ) -> Self {
        Handle {
            inner: handle,
        }
    }

    /// Get the hardware info for that packet.
    pub fn info(&self) -> &Info {
        self.inner.info()
    }

    /// Proof to the compiler that we can shorten the lifetime arbitrarily.
    pub fn borrow_mut(&mut self) -> Handle {
        Handle {
            inner: self.inner.borrow_mut(),
        }
    }
}

impl<'a, P: Payload> Packet<'a, P> {
    pub(crate) fn new(
        handle: Handle<'a>,
        packet: UdpPacket<ip::IpPacket<'a, P>>)
    -> Self {
        Packet {
            handle,
            packet,
        }
    }

    pub fn reinit(self) -> RawPacket<'a, P>
        where P: PayloadMut,
    {
        RawPacket::new(self.handle, self.packet.into_inner().into_raw())
    }

    /// Called last after having initialized the payload.
    pub fn send(mut self) -> Result<()>
        where P: PayloadMut,
    {
        let capabilities = self.handle.info().capabilities();
        let ip_repr = self.packet.get_ref().repr();
        let checksum = capabilities.udp().tx_checksum(ip_repr);
        self.packet.fill_checksum(checksum);
        let lower = ip::Packet::new(
            self.handle.inner,
            self.packet.into_inner());
        lower.send()
    }
}

impl<'a, P: Payload + PayloadMut> RawPacket<'a, P> {
    pub(crate) fn new(
        handle: Handle<'a>,
        payload: &'a mut P,
    ) -> Self {
        RawPacket {
            handle,
            payload,
        }
    }

    /// Initialize to a valid ip packet.
    pub fn prepare(self, init: Init) -> Result<Packet<'a, P>> {
        let lower = ip::RawPacket::new(
            self.handle.inner,
            self.payload);

        let lower_init = ip::Init {
            src_mask: init.src_mask,
            dst_addr: init.dst_addr,
            protocol: IpProtocol::Udp,
            payload: init.payload + 8,
        };

        let mut prepared = lower.prepare(lower_init)?;
        let repr = init.initialize(&mut prepared.packet)?;

        // Reconstruct the handle.
        let handle = Handle::new(prepared.handle);

        Ok(Packet {
            handle,
            packet: UdpPacket::new_unchecked(prepared.packet, repr),
        })
    }
}

impl Init {
    fn initialize(&self, payload: &mut impl PayloadMut) -> Result<UdpRepr> {
        let repr = UdpRepr {
            src_port: self.src_port,
            dst_port: self.dst_port,
            length: u16::try_from(self.payload)
                .map_err(|_| Error::BadSize)?,
        };

        // Assumes length was already dealt with.
        let packet = udp_packet::new_unchecked_mut(
            payload.payload_mut().as_mut_slice());
        repr.emit(packet, UdpChecksum::Ignored);

        Ok(repr)
    }
}
