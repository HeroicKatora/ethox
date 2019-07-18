use crate::layer::ip;
use crate::wire::{Reframe, Payload, PayloadMut, PayloadResult, payload};
use crate::wire::{IpProtocol, TcpPacket, TcpRepr, TcpSeqNumber};

use super::connection::{Endpoint, InPacket, Operator, Signals};
use super::endpoint::{FourTuple, SlotKey};

/// An incoming tcp packet.
///
/// Don't worry, you can't really do anything with it yet. Not that you'd want to because
/// connections are always closed or not actually responding.
pub enum In<'a, P: PayloadMut> {
    /// A packet that elicited an immediate response.
    ///
    /// May be interesting for logging this but you may as well drop this variant immediately.
    Sending(Sending<'a>),

    /// There is an open connection and you may send and receive data.
    Open(Open<'a, P>),

    /// A packet from us will close the connection.
    ///
    /// This is very similar to `Sending` but it no longer contains a valid connection.
    Closing(Closing<'a>),

    /// Connection has just been closed by the packet.
    Closed(Stray<'a, P>),

    /// A packet for no connection arrived.
    ///
    /// Maybe you are interested anyways? At least the packet was valid tcp traffic and maybe you
    /// want to retro-actively open a new, due some funny port-knocking business or w/e. Your hacks
    /// stay your own, and keep the bugs you find along the way.
    Stray(Stray<'a, P>),
}

pub trait SendBuf {
    /// Check the available data.
    ///
    /// This should be the total of previously sent bytes and unsent bytes.
    fn available(&self) -> usize;

    /// Fill in some retransmited data.
    ///
    /// The tcp connection layer will take care to never call this with a buffer outside the
    /// indicated available data length. Bytes that have already been sent are not supposed to
    /// change afterwards, i.e. the `SendBuf` is also utilized as the retransmit buffer.
    fn fill(&mut self, buf: &mut [u8], begin: TcpSeqNumber);

    /// Notify the buffer that some data can be safely discarded.
    ///
    /// The tcp layer will ensure that no data before the new `begin` is requested again.
    fn ack(&mut self, begin: TcpSeqNumber);
}

pub trait RecvBuf {
    /// Accept some incoming data.
    ///
    /// Report back the new unreceived byte. This allows the receive buffer to choose the strategy
    /// for partially acknowledged data.
    fn receive(&mut self, buf: &[u8], begin: TcpSeqNumber);

    /// Get the highest completed sequence number.
    fn ack(&mut self) -> TcpSeqNumber;

    /// Get the current window size.
    ///
    /// Shrinking the window size without having accepted new data is allowed but strongly
    /// discouraged.
    fn window(&self) -> usize;
}

/// Packet representation *after* it has been applied to its connection.
///
/// This is purely internal to transition to the handled `In` state.
enum Unhandled<'a, P: Payload> {
    Open {
        operator: Operator<'a>,
        tcp: TcpPacket<ip::IpPacket<'a, P>>,
    },
    Closed {
        endpoint: &'a mut Endpoint,
        tcp: TcpPacket<ip::IpPacket<'a, P>>,
    },
}

/// There was some content to send **immediately**.
///
/// The packet has been prepared and already queued on the socket. Not handling or dropping the
/// packet structure now will emit the packet.
///
/// Note that there may still be data that can be received, or the possibility to piggy-back more
/// data to be sent onto the packet. There are flags to test for this.
pub struct Sending<'a> {
    operator: Operator<'a>,
    signals: Signals,
}

/// A closing message from us.
/// 
/// Same as `Sending`, the packet has already been prepared and queue.
pub struct Closing<'a> {
    endpoint: &'a mut Endpoint,
    signals: Signals,
}

/// An open connection on which we might want to send and receive data.
///
/// Reading of incoming data and sending of ones own is largely independent of each other.
pub struct Open<'a, P: PayloadMut> {
    ip: ip::Handle<'a>,
    operator: Operator<'a>,
    signals: Signals,
    tcp: TcpPacket<ip::IpPacket<'a, P>>,
}

/// A valid tcp packet not belonging to a connection.
pub struct Stray<'a, P: PayloadMut> {
    endpoint: &'a mut Endpoint,
    tcp: TcpPacket<ip::IpPacket<'a, P>>,
}

impl<'a, P: PayloadMut> Unhandled<'a, P> {
    pub fn try_open(
        endpoint: &'a mut Endpoint,
        tcp: TcpPacket<ip::IpPacket<'a, P>>,
    ) -> Self {
        let tcp_repr = tcp.repr();
        let ip_repr = tcp.inner().repr();

        let connection = FourTuple {
            local: ip_repr.src_addr(),
            local_port: tcp_repr.dst_port,
            remote: ip_repr.dst_addr(),
            remote_port: tcp_repr.src_port,
        };

        match Operator::from_tuple(endpoint, connection) {
            Ok(operator) => Unhandled::Open {
                operator,
                tcp,
            },
            Err(endpoint) => Unhandled::Closed {
                endpoint,
                tcp,
            }
        }
    }
}

impl<'a, P: PayloadMut> In<'a, P> {
    pub fn from_arriving(
        endpoint: &'a mut Endpoint,
        ip_control: ip::Handle<'a>,
        tcp: TcpPacket<ip::IpPacket<'a, P>>,
    ) -> Result<Self, crate::layer::Error> {
        let (mut operator, tcp) = match Unhandled::try_open(endpoint, tcp) {
            Unhandled::Open { operator, tcp } => (operator, tcp),
            Unhandled::Closed { endpoint, tcp } => {
                return Ok(In::Stray(Stray {
                    endpoint,
                    tcp,
                }));
            }
        };

        let from = tcp.inner().repr().src_addr();
        let time = ip_control.info().timestamp();
        let in_packet = InPacket {
            segment: tcp.repr(),
            from,
            time,
        };

        let mut signals = operator.arrives(&in_packet);

        // Deleting the connection nothing to be sent.
        if signals.delete && signals.answer.is_none() {
            debug_assert_eq!(signals.receive, false);
            debug_assert_eq!(signals.may_send, false);
            let endpoint = operator.delete();
            // TODO: Propagate `reset` bit
            return Ok(In::Closed(Stray {
                endpoint,
                tcp,
            }));
        }

        // If no answer we are free to send anything.
        let answer = match signals.answer.take() {
            Some(answer) => answer,
            None => {
                // We can not be forced to drop this.
                debug_assert_eq!(signals.may_send, true);
                debug_assert_eq!(signals.reset, false);
                debug_assert_eq!(signals.delete, false);
                return Ok(In::Open(Open {
                    ip: ip_control,
                    operator,
                    signals,
                    tcp,
                }));
            },
        };

        // Prepare the answer packet itself.

        control_answer(tcp, answer, ip_control)?;

        // We need to close the connection. The sent packet should be an RST.
        if signals.delete {
            let endpoint = operator.delete();
            return Ok(In::Closing(Closing {
                endpoint,
                signals,
            }));
        }

        debug_assert_eq!(signals.reset, false);
        Ok(In::Sending(Sending {
            operator,
            signals,
        }))
    }
}

impl<'a, P: PayloadMut> Open<'a, P> {
    pub fn key(&self) -> SlotKey {
        self.operator.connection_key
    }

    pub fn read(&self, with: &mut impl RecvBuf) {
        let payload = self.tcp.payload_slice();
        with.receive(payload, self.tcp.seq_number());
    }

    pub fn write(mut self, with: &mut impl SendBuf) -> Result<Sending<'a>, Self> {
        let available = with.available();
        let time = self.ip.info().timestamp();
        let range = self.operator.next_send_segment(available, time);
        unimplemented!()
    }
}

fn control_answer<'a, P: PayloadMut>(
    tcp: TcpPacket<ip::IpPacket<'a, P>>,
    answer: TcpRepr,
    ip: ip::Handle<'a>,
) -> Result<(), crate::layer::Error> {
    assert_eq!(answer.payload_len, 0, "Control answer can not handle data");

    let raw_buffer = tcp.into_inner();
    let ip_repr = raw_buffer.repr();
    let ip_payload_len = answer.header_len();

    let packet = ip::InPacket {
        handle: ip,
        packet: raw_buffer,
    };

    // Send a packet back.
    let ip::InPacket { handle, mut packet, } = packet.reinit(ip::Init {
        source: ip::Source::Exact(ip_repr.dst_addr()),
        dst_addr: ip_repr.src_addr(),
        protocol: IpProtocol::Tcp,
        payload: ip_payload_len,
    })?.into_incoming();

    let raw_packet = TcpPacket::new_unchecked(&mut packet, answer.clone());
    answer.emit(raw_packet);

    ip::OutPacket::new_unchecked(handle, packet)
        .send()
}
