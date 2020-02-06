use crate::layer::{self, FnHandler, Result};
use crate::wire::{icmpv4, ip, Error, Payload, PayloadMut};

use super::packet::{Controller, In, Raw};
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
/// [WIP]: What state is actually necessary for an icmp endpoint? Answering pings takes a single
/// flag and there is an RFC recommending to do automatic responses where possible without
/// involving an upper layer. But I suppose there could be some config involved in router
/// solicitation, timestamps, icmp extended echo authorization, ...
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
    _endpoint: EndpointRef<'a>,

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
    /// Create a new endpoint with a default configuration.
    ///
    /// The default will answer echo requests to the IP addresses configured for the underlying
    /// layer, and the hardware address of the interface. It will also not allow customized
    /// interception of ICMP messages that have default semantics and responses.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set manual mode for responses (off by default).
    ///
    /// This will forward all packets to the upper layer where they can be answered in the default
    /// way, dropped, but also answered with customization. However, packets will no longer be
    /// answered without upper layer intervention, e.g. `answer` will no longer do anything.
    ///
    /// There are some applications for this. Firstly, a middlebox might want to avoid responses to
    /// appear more transparent, or maybe answer only to *some* source addresses as a simple means
    /// of uptime testing. Secondly, a penetration testing application could appear more stealthy,
    /// confuse network analysis or try to use ICMP to fake a different topology by mismatching
    /// echo responses. (Maybe decrease the TTL in sent echo packets to give the appearance of
    /// intermediate NAT. Do exfiltration through the TTL, sequence number and ident. You'll come
    /// up with own ideas probably. Try things out, that's the whole point why this library was
    /// written.)
    pub fn manual(&mut self, manual: bool) {
        self.manual_echo = manual;
    }

    /// Set whether to generate answers for echo requests (and similar).
    ///
    /// While in automatic mode, setting `silent` to `true` will drop echo requests instead of
    /// answering them. This has no influence on packet handling in manual mode.
    pub fn silent(&mut self, silent: bool) {
        self.deny_echo = silent;
    }

    /// A receiver that only answers pings in the default manner.
    pub fn answer(&mut self) -> Receiver {
        Receiver { endpoint: self.get_mut(), handler: None, }
    }

    /// Receive packet using this mutably borrowed endpoint.
    pub fn recv<H>(&mut self, handler: H) -> Receiver<H> {
        Receiver { endpoint: self.get_mut(), handler: Some(handler), }
    }

    /// Receive packet using this mutably borrowed endpoint and a function.
    pub fn recv_with<H>(&mut self, handler: H) -> Receiver<FnHandler<H>> {
        self.recv(FnHandler(handler))
    }

    /// Send packets using this mutably borrowed endpoint.
    pub fn send<H>(&mut self, handler: H) -> Sender<H> {
        Sender { _endpoint: self.get_mut(), handler, }
    }

    /// Send packets using this mutably borrowed endpoint and a function.
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
            icmpv4::Repr::EchoRequest { .. } if self.inner.manual_echo => {
                Ok(HandlingKind::ToUpperLayer(packet))
            },
            icmpv4::Repr::EchoRequest { .. } => {
                if self.inner.deny_echo {
                    return Ok(HandlingKind::Internal)
                }

                packet
                    .answer()?
                    .send()?;

                Ok(HandlingKind::Internal)
            },
            _ => Ok(HandlingKind::ToUpperLayer(packet)),
        }
    }
}

impl<P, H> layer::ip::Recv<P> for Receiver<'_, H>
where
    P: PayloadMut,
    H: Recv<P>,
{
    fn receive(&mut self, layer::ip::InPacket { control, packet }: layer::ip::InPacket<P>) {
        let capabilities = control.info().capabilities();

        let icmp = match packet {
            layer::ip::IpPacket::V4(packet) => {
                if packet.repr().protocol != ip::Protocol::Icmp {
                    return;
                }

                match icmpv4::Packet::new_checked(packet, capabilities.icmpv4().rx_checksum()) {
                    Ok(packet) => packet,
                    Err(Error::Unsupported) => unimplemented!("Forward to upper layer"),
                    Err(_) => return,
                }
            },
            // Handle icmpv6
            _ => return,
        };

        let control = Controller { inner: control };
        let packet = In { control, packet: icmp };

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

impl<P, T> layer::ip::Send<P> for Sender<'_, T>
where
    P: PayloadMut,
    T: Send<P>,
{
    fn send(&mut self, packet: layer::ip::RawPacket<P>) {
        let layer::ip::RawPacket { control: mut eth_handle, payload } = packet;

        self.handler.send(Raw {
            control: Controller {
                inner: eth_handle.borrow_mut()
            },
            payload,
        })
    }
}

impl<P: PayloadMut> Recv<P> for NoHandler {
    fn receive(&mut self, _: In<P>) {
        match self._private { }
    }
}

impl<P: Payload, F> Recv<P> for FnHandler<F>
    where F: FnMut(In<P>)
{
    fn receive(&mut self, frame: In<P>) {
        self.0(frame)
    }
}

impl<P: Payload, F> Send<P> for FnHandler<F>
    where F: FnMut(Raw<P>)
{
    fn send(&mut self, frame: Raw<P>) {
        self.0(frame)
    }
}
