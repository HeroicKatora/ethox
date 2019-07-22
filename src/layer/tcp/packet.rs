use crate::layer::ip;
use crate::wire::{Reframe, Payload, PayloadMut, PayloadResult, payload};
use crate::wire::{IpAddress, IpProtocol, TcpPacket, TcpRepr, TcpSeqNumber};

use super::connection::{Endpoint, InPacket, Operator, Segment, Signals};
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
    Closed(Closed<'a, P>),

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
    previous: SlotKey,
    signals: Signals,
}

/// A connection was closed by a remote packet.
///
/// Similar to a `Stray` packet but we retain which connection was closed.
pub struct Closed<'a, P: PayloadMut> {
    ip: ip::Handle<'a>,
    endpoint: &'a mut Endpoint,
    previous: SlotKey,
    tcp: TcpPacket<ip::IpPacket<'a, P>>,
}

/// An open connection on which we might want to send and receive data.
///
/// Reading of incoming data and sending of ones own is largely independent of each other.
pub struct Open<'a, P: PayloadMut> {
    ip: ip::Handle<'a>,
    operator: Operator<'a>,
    signals: Signals,
    packet: OpenPacket<'a, P>,
}

/// A valid tcp packet not belonging to a connection.
pub struct Stray<'a, P: PayloadMut> {
    ip: ip::Handle<'a>,
    endpoint: &'a mut Endpoint,
    tcp: TcpPacket<ip::IpPacket<'a, P>>,
}

enum OpenPacket<'a, P: PayloadMut> {
    /// There is an incoming packet and data to be read.
    In {
        tcp: TcpPacket<ip::IpPacket<'a, P>>,
    },

    /// We got this from the outgoing direction, no data to read.
    Out {
        raw: &'a mut P,
    },
}

/// A raw opportunity to create a packet.
pub struct Raw<'a, P: PayloadMut> {
    ip: ip::RawPacket<'a, P>,
    endpoint: &'a mut Endpoint,
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
                    ip: ip_control,
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
            let previous = operator.connection_key;
            let endpoint = operator.delete();
            // TODO: Propagate `reset` bit
            return Ok(In::Closed(Closed {
                ip: ip_control,
                endpoint,
                previous,
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
                    packet: OpenPacket::In { tcp },
                }));
            },
        };

        // Prepare the answer packet itself.

        control_answer(tcp, answer, ip_control)?;

        // We need to close the connection. The sent packet should be an RST.
        if signals.delete {
            let previous = operator.connection_key;
            let endpoint = operator.delete();
            return Ok(In::Closing(Closing {
                endpoint,
                previous,
                signals,
            }));
        }

        debug_assert_eq!(signals.reset, false);
        Ok(In::Sending(Sending {
            operator,
            signals,
        }))
    }

    pub fn key(&self) -> Option<SlotKey> {
        match self {
            In::Sending(sending) => Some(sending.key()),
            In::Open(open) => Some(open.key()),
            In::Closing(closing) => Some(closing.key()),
            In::Closed(closed) => Some(closed.key()),
            In::Stray(_) => None,
        }
    }
}

impl<'a, P: PayloadMut> Open<'a, P> {
    pub fn key(&self) -> SlotKey {
        self.operator.connection_key
    }

    pub fn read(&self, with: &mut impl RecvBuf) {
        if let OpenPacket::In { tcp } = &self.packet {
            let payload = tcp.payload_slice();
            with.receive(payload, tcp.seq_number());
        }
    }

    /// Try to send parts of the available data.
    ///
    /// If the method succeeds returns a view on the packet being sent. Else, it will return a
    /// handle to the connection again (this struct).
    ///
    /// Any data that is currently held as an incoming packet will be lost, even if this method fails.
    pub fn write(self, with: &mut impl SendBuf) -> Result<Sending<'a>, crate::layer::Error> {
        let Open { ip, mut operator, signals: _, packet, } = self;
        let payload: &'a mut P = match packet {
            OpenPacket::In { tcp } => tcp.into_inner().into_inner().into_inner(),
            OpenPacket::Out { raw } => raw,
        };

        let tcp_seq = operator.connection().send.unacked;
        with.ack(tcp_seq);
        let available = with.available();
        let time = ip.info().timestamp();

        let Segment { repr, range } = match operator.next_send_segment(available, time) {
            Some(segment) => segment,
            None => return Err(crate::layer::Error::Illegal),
        };

        let raw_ip = ip::RawPacket {
            handle: ip,
            payload,
        };

        let mut out_ip = prepare(raw_ip, &mut operator, repr)?;
        let mut tcp = TcpPacket::new_unchecked(out_ip.payload_mut_slice(), repr);
        with.fill(tcp.payload_mut_slice(), tcp_seq + range.start);

        out_ip.send()?;

        Ok(Sending {
            operator,
            signals: Signals::default(),
        })
    }
}

impl<'a, P: PayloadMut> Raw<'a, P> {
    /// Create a new connection.
    pub fn open(self, addr: IpAddress, port: u16) -> Result<Sending<'a>, crate::layer::Error> {
        let new = FourTuple {
            local: addr,
            local_port: port,
            remote: IpAddress::Unspecified,
            remote_port: 0,
        };

        let mut operator = match self.endpoint.open(new) {
            None => return Err(crate::layer::Error::Exhausted),
            Some(key) => Operator::new(self.endpoint, key).unwrap(),
        };

        let time = self.ip.handle.info().timestamp();
        let repr = operator.open(time)?;
        let out_ip = prepare(self.ip, &mut operator, repr)?;
        out_ip.send()?;

        Ok(Sending {
            operator,
            signals: Signals::default(),
        })
    }

    /// Attach to an existing connection.
    ///
    /// If successful, this return an `Open` packet with which you can send data on the connection.
    pub fn attach(self, key: SlotKey) -> Result<Open<'a, P>, Self> {
        if self.endpoint.get(key).is_none() {
            return Err(self);
        };

        let operator = Operator::new(self.endpoint, key).unwrap();

        let ip::RawPacket {
            handle: ip,
            payload: raw,
        } = self.ip;

        Ok(Open {
            operator,
            signals: Signals::default(),
            ip,
            packet: OpenPacket::Out { raw },
        })
    }
}

impl<'a> Sending<'a> {
    pub fn key(&self) -> SlotKey {
        self.operator.connection_key
    }
}

impl<'a> Closing<'a> {
    pub fn key(&self) -> SlotKey {
        self.previous
    }
}

impl<'a, P: PayloadMut> Closed<'a, P> {
    pub fn key(&self) -> SlotKey {
        self.previous
    }

    pub fn into_raw(self) -> Raw<'a, P> {
        let raw_ip = ip::RawPacket {
            handle: self.ip,
            payload: self.tcp.into_inner().into_inner().into_inner(),
        };

        Raw {
            ip: raw_ip,
            endpoint: self.endpoint,
        }
    }
}

impl<'a, P: PayloadMut> Stray<'a, P> {
    pub fn into_raw(self) -> Raw<'a, P> {
        let raw_ip = ip::RawPacket {
            handle: self.ip,
            payload: self.tcp.into_inner().into_inner().into_inner(),
        };

        Raw {
            ip: raw_ip,
            endpoint: self.endpoint,
        }
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

fn prepare<'a, P: PayloadMut>(
    packet: ip::RawPacket<'a, P>,
    operator: &mut Operator,
    repr: TcpRepr,
) -> Result<ip::OutPacket<'a, P>, crate::layer::Error> {

    let tuple = operator.four_tuple();
    let init_ip = packet.prepare(ip::Init {
        dst_addr: tuple.remote,
        source: ip::Source::Exact(tuple.local),
        protocol: IpProtocol::Tcp,
        payload: repr.header_len() + usize::from(repr.payload_len),
    })?;

    let ip::InPacket { handle, mut packet } = init_ip.into_incoming();

    let tcp = TcpPacket::new_unchecked(&mut packet, repr);
    repr.emit(tcp);

    Ok(ip::OutPacket::new_unchecked(handle, packet))
}
