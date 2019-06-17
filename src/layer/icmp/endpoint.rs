use crate::layer::{ip, FnHandler, Result};
use crate::wire::{Error, Icmpv4Repr, Icmpv4Packet, IpProtocol, PayloadMut};

use super::packet::{Handle, In};
use super::{Recv, Send};

/// The default handler type when none has been configured.
///
/// No instance can be created and should never be. This type provides an implementation of an
/// upper layer receiver but its methods can never be invoked since they can no have a receiver.
/// This has no representation but that is an implementation details that is not otherwise exposed.
pub struct NoHandler { _private: Empty, }

/// An empty enum to prove that there is no instance of `NoHandler`.
enum Empty { }

/// An icmp traffic handler.
///
/// [WIP]: No idea what state is necessary for an icmp endpoint? Answering pings at least doesn't
/// take any. Suppose there could be some config involved in router solicitation, timestamps, icmp
/// extended echo authorization, ...
#[derive(Default)]
pub struct Endpoint {
    /// Drops echo requests if enabled.
    ///
    /// This is off by default, as required in RFC1812, but can be enabled to avoid answering echo
    /// requests on some node. Might be done for some routers.
    deny_echo: bool,

    /// Determine if all echos are forwarded to the upper handler.
    ///
    /// If enabled but no handler is configured then these requests are simply dropped.
    manual_echo: bool,
}

/// An endpoint borrowed for receiving.
///
/// Dispatching to higher protocols is configured here, and not in the endpoint state.
pub struct Receiver<'a, H=NoHandler> {
    endpoint: EndpointRef<'a>,

    /// The receiver for any unhandled messages.
    handler: Option<H>,
}

/// An icmp endpoint for sending.
pub struct Sender<'a, H> {
    endpoint: EndpointRef<'a>,

    /// The upper protocol sender.
    handler: H,
}

struct EndpointRef<'a> {
    inner: &'a Endpoint,
}

enum HandlingKind<'a, P: PayloadMut> {
    /// The upper layer handler should not need to see this packet.
    Internal,

    /// Give the packet to upper layer handler if that exists.
    ToUpperLayer(In<'a, P>),
}

impl Endpoint {
    pub fn new() -> Self {
        Self::default()
    }

    /// A receiver that only answers pings.
    pub fn answer(&mut self) -> Receiver {
        Receiver { endpoint: self.get_mut(), handler: None, }
    }

    pub fn recv<H>(&mut self, handler: H) -> Receiver<H> {
        Receiver { endpoint: self.get_mut(), handler: Some(handler), }
    }

    pub fn recv_with<H>(&mut self, handler: H) -> Receiver<FnHandler<H>> {
        self.recv(FnHandler(handler))
    }

    pub fn send<H>(&mut self, handler: H) -> Sender<H> {
        Sender { endpoint: self.get_mut(), handler, }
    }

    pub fn send_with<H>(&mut self, handler: H) -> Sender<FnHandler<H>> {
        self.send(FnHandler(handler))
    }

    /// Get this by mutable reference for a receiver or sender.
    // Mutable technically unused but not sure right now.
    fn get_mut(&mut self) -> EndpointRef {
        EndpointRef { inner: self }
    }
}

impl EndpointRef<'_> {
    /// Try to answer or otherwise handle the packet without propagating it upwards.
    fn handle_internally<'a, P: PayloadMut>(&mut self, packet: In<'a, P>)
        -> Result<HandlingKind<'a, P>>
    {
        match packet.packet.repr() {
            Icmpv4Repr::EchoRequest { .. } if self.inner.manual_echo => {
                Ok(HandlingKind::ToUpperLayer(packet))
            },
            Icmpv4Repr::EchoRequest { .. } => {
                if self.inner.deny_echo {
                    return Ok(HandlingKind::Internal)
                }

                packet.answer()?;

                Ok(HandlingKind::Internal)
            },
            _ => Ok(HandlingKind::ToUpperLayer(packet)),
        }
    }
}

impl<P, H> ip::Recv<P> for Receiver<'_, H>
where
    P: PayloadMut,
    H: Recv<P>,
{
    fn receive(&mut self, ip::InPacket { handle, packet }: ip::InPacket<P>) {
        let capabilities = handle.info().capabilities();

        let icmp = match packet {
            ip::IpPacket::V4(packet) => {
                if packet.repr().protocol != IpProtocol::Icmp {
                    return;
                }

                match Icmpv4Packet::new_checked(packet, capabilities.icmpv4().rx_checksum()) {
                    Ok(packet) => packet,
                    Err(Error::Unsupported) => unimplemented!("Forward to upper layer"),
                    Err(_) => return,
                }
            },
            // Handle icmpv6
            _ => return,
        };

        let handle = Handle::new(handle);
        let packet = In::new(handle, icmp);

        let how_to_handle = match self.endpoint.handle_internally(packet) {
            Ok(handling) => handling,
            Err(_) => return,
        };

        match (how_to_handle, self.handler.as_mut()) {
            (HandlingKind::Internal, _) => (),
            (HandlingKind::ToUpperLayer(packet), Some(handler)) => {
                handler.receive(packet)
            },
            _ => (),
        }
    }
}
