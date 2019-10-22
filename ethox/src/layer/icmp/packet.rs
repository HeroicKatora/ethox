use crate::nic::Info;
use crate::layer::{Error, Result, ip};
use crate::wire::{Payload, PayloadMut};
use crate::wire::{Checksum, IpAddress, IpProtocol};
use crate::wire::{Icmpv4Packet, Icmpv4Repr, icmpv4_packet};

/// An incoming packet.
///
/// The contents were inspected and could be handled up to the icmp layer. The upper layer handler
/// will only receive packets that could not be handled natively by the network library. Pings can
/// be answered in-place without involving the upper layer if supported by the nic.
pub struct In<'a, P: Payload> {
    /// A reference to the ICMP endpoint state.
    pub control: Controller<'a>,
    /// The valid packet inside the buffer.
    pub packet: Icmpv4Packet<ip::V4Packet<'a, P>>,
}

/// An outgoing packet as prepared by the icmp layer.
///
/// Some packets have variable payloads [WIP]. These also contribute to the checksum and are yet to
/// be initialized.
#[must_use = "You need to call `send` explicitely on an OutPacket, otherwise no packet is sent."]
pub struct Out<'a, P: Payload> {
    control: Controller<'a>,
    packet: Icmpv4Packet<ip::V4Packet<'a, P>>,
}

/// A buffer into which a packet can be placed.
pub struct Raw<'a, P: Payload> {
    /// A reference to the ICMP endpoint state.
    pub control: Controller<'a>,
    /// A mutable reference to the payload buffer.
    pub payload: &'a mut P,
}

/// A reference to the endpoint of layers below (phy + eth + ip).
///
/// This is not really useful on its own but should instead be used either within a `In` or a
/// `Raw`. Some of the methods offered there will access the non-public members of this struct to
/// fulfill their task.
pub struct Controller<'a> {
    pub(crate) inner: ip::Controller<'a>,
}

/// A helper struct for packet initialization.
///
/// In other layers the equivalent utilizes the endpoint itself for specialized initialization but
/// the ICMP endpoint has almost no state. The [`RawPacket::prepare`] method thus mostly wraps
/// packet buffer initialization that could be implemented by the user, in a slightly more
/// ergonomic interface.
pub enum Init {
    /// An initializer for an echo request, expecting an echo response by the identified remote
    /// party.
    EchoRequest {
        /// The network source address to use.
        ///
        /// You likely want to use an address that was configured in the IP layer so that the
        /// response will actually be forwarded accordingly.
        source: ip::Source,
        /// The network destination address to query.
        dst_addr: IpAddress,
        /// An arbitrary identifier for the requested.
        ident: u16,
        /// A sequence number for repeated requests.
        seq_no: u16,
        /// The length of user defined payload.
        ///
        /// The content is likely ignored by the receiver, other than being echoed back.
        payload: usize,
    },
}

impl<'a> Controller<'a> {
    /// Get the hardware info for that packet.
    pub fn info(&self) -> &dyn Info {
        self.inner.info()
    }

    /// Proof to the compiler that we can shorten the lifetime arbitrarily.
    pub fn borrow_mut(&mut self) -> Controller {
        Controller {
            inner: self.inner.borrow_mut(),
        }
    }
}

impl<'a, P: Payload> In<'a, P> {
    /// Deconstruct the packet into the reusable buffer.
    pub fn deinit(self) -> Raw<'a, P>
        where P: PayloadMut,
    {
        Raw {
            control: self.control,
            payload: self.packet.into_inner().into_inner().into_inner(),
        }
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
            control: self.control.inner,
            packet: ip::IpPacket::V4(ipv4_packet),
        };

        let ip_out = ip_in.reinit(ip::Init {
            // Be sure to send from this exact address.
            source: IpAddress::from(ip_repr.dst_addr).into(),
            dst_addr: ip_repr.src_addr.into(),
            protocol: IpProtocol::Icmp,
            payload: ip_repr.payload_len,
        })?;

        // Temporarily take the packet apart for inner repr.
        let ip::InPacket { control, mut packet } = ip_out.into_incoming();
        answer.emit(
            icmpv4_packet::new_unchecked_mut(packet.payload_mut().as_mut_slice()),
            Checksum::Manual);
        let packet = match packet {
            ip::IpPacket::V4(packet) => packet,
            ip::IpPacket::V6(_) => unreachable!("No icmpv6 outgoing traffic"),
        };

        Ok(Out {
            control: Controller { inner: control },
            packet: Icmpv4Packet::new_unchecked(packet, answer),
        })
    }
}


impl<'a, P: Payload> Out<'a, P> {
    /// Called last after having initialized the payload.
    pub fn send(mut self) -> Result<()>
        where P: PayloadMut,
    {
        let capabilities = self.control.info().capabilities();
        let checksum = capabilities.icmpv4().tx_checksum();
        self.packet.fill_checksum(checksum);
        let lower = ip::OutPacket::new_unchecked(
            self.control.inner,
            ip::IpPacket::V4(self.packet.into_inner()));
        lower.send()
    }
}

impl<'a, P: PayloadMut> Out<'a, P> {
    /// A mutable slice containing the payload of the icmp message.
    ///
    /// The semantics of the payload differ for the defined operations. See a guide to ICMP for the
    /// details.
    ///
    /// This function will also work for ICMPv6 (currently unimplemented).
    pub fn payload_mut_slice(&mut self) -> &mut [u8] {
        self.packet.payload_mut_slice()
    }
}

impl<'a, P: Payload + PayloadMut> Raw<'a, P> {
    /// Initialize to a valid ip packet.
    pub fn prepare(self, init: Init) -> Result<Out<'a, P>> {
        let lower = ip::RawPacket {
            control: self.control.inner,
            payload: self.payload,
        };

        let lower_init = init.ip_init()?;
        let prepared = lower.prepare(lower_init)?;
        let ip::InPacket { control, packet } = prepared.into_incoming();

        let mut packet = match packet {
            ip::IpPacket::V4(packet) => packet,
            ip::IpPacket::V6(_) => unreachable!(),
        };
        let repr = init.initialize(&mut packet)?;

        Ok(Out {
            control: Controller { inner: control },
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
            Init::EchoRequest { source, payload, dst_addr, .. } => {
                let len = payload
                    .checked_add(8)
                    .ok_or(Error::BadSize)?;
                ip::Init {
                    source,
                    dst_addr,
                    protocol: IpProtocol::Icmp,
                    payload: len,
                }
            },
        })
    }
}
