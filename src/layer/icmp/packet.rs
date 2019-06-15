use crate::nic::Info;
use crate::layer::{Error, Result, ip};
use crate::wire::{Payload, PayloadMut};
use crate::wire::{Checksum, IpAddress, IpCidr, IpProtocol};
use crate::wire::{Icmpv4Packet, Icmpv4Repr, icmpv4_packet};

pub struct Packet<'a, P: Payload> {
    pub handle: Handle<'a>,
    pub packet: Icmpv4Packet<ip::V4Packet<'a, P>>,
}

pub struct RawPacket<'a, P: Payload> {
    pub handle: Handle<'a>,
    pub payload: &'a mut P,
}

/// A reference to the endpoint of layers below (phy + eth + ip).
///
/// This is not really useful on its own but should instead be used either within a `Packet` or a
/// `RawPacket`. Some of the methods offered there will access the non-public members of this
/// struct to fulfill their task.
pub struct Handle<'a> {
    pub(crate) inner: ip::Handle<'a>,
    // Nothing more, there is no logic here.
}

pub enum Init {
    EchoRequest {
        src_mask: IpCidr,
        dst_addr: IpAddress,
        ident: u16,
        seq_no: u16,
        payload: usize,
    },
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
        packet: Icmpv4Packet<ip::V4Packet<'a, P>>)
    -> Self {
        Packet {
            handle,
            packet,
        }
    }

    pub fn reinit(self) -> RawPacket<'a, P>
        where P: PayloadMut,
    {
        RawPacket::new(self.handle, self.packet.into_inner().into_inner().into_inner())
    }

    /// Called last after having initialized the payload.
    pub fn send(mut self) -> Result<()>
        where P: PayloadMut,
    {
        let capabilities = self.handle.info().capabilities();
        let checksum = capabilities.icmpv4().tx_checksum();
        self.packet.fill_checksum(checksum);
        let lower = ip::OutPacket::new_unchecked(
            self.handle.inner,
            ip::IpPacket::V4(self.packet.into_inner()));
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

        let lower_init = init.ip_init()?;
        let prepared = lower.prepare(lower_init)?;
        let ip::InPacket { handle, packet } = prepared.into_incoming();

        let mut packet = match packet {
            ip::IpPacket::V4(packet) => packet,
            ip::IpPacket::V6(_) => unreachable!(),
        };
        let repr = init.initialize(&mut packet)?;

        // Reconstruct the handle.
        let handle = Handle::new(handle);

        Ok(Packet {
            handle,
            packet: Icmpv4Packet::new_unchecked(packet, repr),
        })
    }
}

impl Init {
    fn initialize(&self, payload: &mut impl PayloadMut) -> Result<Icmpv4Repr> {
        let repr = self.repr();

        // Assumes length was already dealt with.
        let packet = icmpv4_packet::new_unchecked_mut(
            payload.payload_mut().as_mut_slice());
        repr.emit(packet, Checksum::Ignored);

        Ok(repr)
    }

    fn repr(&self) -> Icmpv4Repr {
        match *self {
            Init::EchoRequest { ident, seq_no, payload, .. } => {
                Icmpv4Repr::EchoRequest { ident, seq_no, payload }
            },
        }
    }

    fn ip_init(&self) -> Result<ip::Init> {
        Ok(match *self {
            Init::EchoRequest { src_mask, payload, dst_addr, .. } => {
                let len = payload
                    .checked_add(8)
                    .ok_or(Error::BadSize)?;
                ip::Init {
                    src_mask,
                    dst_addr,
                    protocol: IpProtocol::Icmp,
                    payload: len,
                }
            },
        })
    }
}
