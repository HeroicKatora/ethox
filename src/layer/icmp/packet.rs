use crate::nic::Info;
use crate::layer::{Error, Result, ip};
use crate::wire::{Payload, PayloadMut};
use crate::wire::{Checksum, IpAddress, IpCidr, IpProtocol};
use crate::wire::{Icmpv4Packet, Icmpv4Repr, icmpv4_packet};

/// An incoming packet.
///
/// The contents were inspected and could be handled up to the icmp layer. The upper layer handler
/// will only receive packets that could not be handled natively by the network library. Pings can
/// be answered in-place without involving the upper layer if supported by the nic.
pub struct In<'a, P: Payload> {
    pub handle: Handle<'a>,
    pub packet: Icmpv4Packet<ip::V4Packet<'a, P>>,
}

/// An outgoing packet as prepared by the icmp layer.
///
/// Some packets have variable payloads [WIP]. These also contribute to the checksum and are yet to
/// be initialized.
pub struct Out<'a, P: Payload> {
    handle: Handle<'a>,
    packet: Icmpv4Packet<ip::V4Packet<'a, P>>,
}

/// A buffer into which a packet can be placed.
pub struct Raw<'a, P: Payload> {
    pub handle: Handle<'a>,
    pub payload: &'a mut P,
}

/// A reference to the endpoint of layers below (phy + eth + ip).
///
/// This is not really useful on its own but should instead be used either within a `In` or a
/// `Raw`. Some of the methods offered there will access the non-public members of this struct to
/// fulfill their task.
pub struct Handle<'a> {
    pub(crate) inner: ip::Handle<'a>,
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

impl<'a, P: Payload> In<'a, P> {
    pub(crate) fn new(
        handle: Handle<'a>,
        packet: Icmpv4Packet<ip::V4Packet<'a, P>>)
    -> Self {
        In {
            handle,
            packet,
        }
    }
    pub fn deinit(self) -> Raw<'a, P>
        where P: PayloadMut,
    {
        let payload = self.packet.into_inner().into_inner().into_inner();
        Raw::new(self.handle, payload)
    }
}

impl<'a, P: PayloadMut> In<'a, P> {
    /// Try to answer an icmp ping request in-place.
    pub fn answer(self) -> Result<Out<'a, P>> {
        let answer = match self.packet.repr() {
            Icmpv4Repr::EchoRequest { ident, seq_no, payload } => {
                Icmpv4Repr::EchoReply { ident, seq_no, payload }
            },
            _ => return Err(Error::Illegal),
        };

        // Try to reverse the ip packet.
        let ipv4_packet = self.packet.into_inner();
        let ip_repr = ipv4_packet.repr();
        let ip_in = ip::InPacket {
            handle: self.handle.inner,
            packet: ip::IpPacket::V4(ipv4_packet),
        };

        let ip_out = ip_in.reinit(ip::Init {
            // Be sure to send from this exact address.
            src_mask: IpCidr::new(ip_repr.dst_addr.into(), 32),
            dst_addr: ip_repr.src_addr.into(),
            protocol: IpProtocol::Icmp,
            payload: ip_repr.payload_len,
        })?;

        // Temporarily take the packet apart for inner repr.
        let ip::InPacket { handle, mut packet } = ip_out.into_incoming();
        answer.emit(
            icmpv4_packet::new_unchecked_mut(packet.payload_mut().as_mut_slice()),
            Checksum::Manual);
        let packet = match packet {
            ip::IpPacket::V4(packet) => packet,
            ip::IpPacket::V6(_) => unreachable!("No icmpv6 outgoing traffic"),
        };

        Ok(Out {
            handle: Handle::new(handle),
            packet: Icmpv4Packet::new_unchecked(packet, answer),
        })
    }
}


impl<'a, P: Payload> Out<'a, P> {
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

impl<'a, P: Payload + PayloadMut> Raw<'a, P> {
    pub(crate) fn new(
        handle: Handle<'a>,
        payload: &'a mut P,
    ) -> Self {
        Raw {
            handle,
            payload,
        }
    }

    /// Initialize to a valid ip packet.
    pub fn prepare(self, init: Init) -> Result<Out<'a, P>> {
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

        Ok(Out {
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
