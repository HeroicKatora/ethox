//! The TCP layer abstraction.
//!
//! Offers receiver and sender implementations on top of the ip layer. Some parts differs from
//! lower layers since TCP is a connection oriented protocol but most concepts should be somewhat
//! familiar nevertheless.
//!
//! The main difference is that many incoming events *require* soliciting an answer such as an ACK
//! for received data. In effect, not all `In` packets should be turned into a `Raw` packet and
//! instead should be queued instantaneously. Note: *should*, not *must*. Dropping outgoing packet
//! potentially starves the remote of ACKs and window updates, leading to highly inefficient
//! communication or even resets but not catastrophic failure.
//!
//! There are a number of other simplifying assumptions which we must (but can) refute:
//! * '2-The TCP endpoint has unlimited buffer space'
//!   
//!   This is simply not feasible for an allocation free implementation. TODO: possible, just drop
//!   the packet. This would at least allow it to be used as a `Raw` packet for example for sending
//!   ones own data.
//! * A timer timeout is used to retransmit queue packets. We have no such timer but instead can
//!   utilize being called in `send` to check for that timeout. An alternate check can be deferred
//!   to user code at any point where a send buffer (i.e. a `Raw` packet) is available. The raw
//!   buffer is returned if it was not consumed.
//! * Data can sometimes be piggy-backed on some packets that contain status communication. Note
//!   however that for some networks there is a cost associated with large packet, mostly as higher
//!   drop rates. This may be the case due to badly configured buffers but also congestion avoidance
//!   mechanisms. For these reasons, this is not required but the default `Client` implementation
//!   tries to send as many data carrying segment as possible.
//!
//! ## Structure
//!
//! The main functionality of the ['Endpoint'] structure of this layer is storing the connection
//! states, unlike other layers which mostly store configuration options. To this end it utilizes
//! one generic map of connection tuples to [`SlotKey`]s (which behave similar to specialized file
//! descriptors) and a slotmap of these indices to connections.
//!
//! [`Endpoint`]: struct.Endpoint.html
//! [`SlotKey`]: struct.SlotKey.html
//!
//! Unlike standard stacks where state and user must be assumed to be in different protection
//! domains and which manage their state opaquely, it poses no problem for this library to allow
//! inspection of internal state or modification (by the user) beyond the transitions mandated in
//! the protocol standard.
//!
//! ## Creating a connection
//!
//! An active open to a remote requires sending the initial SYN packet. Thus, the best way to
//! perform this is within a send phase. This requires a [`Raw`] packet and the [`Endpoint`].
//!
//! [`Raw`]: struct.RawPacket.html
//! [`Endpoint`]: struct.Endpoint.html
//!
//! The stack does not *currently* allow sending any data in a SYN packet as these are rarely
//! accepted. They are incompatible with SYN-cookies and otherwise a security and stability risk.
//! As such, they would be mostly useless. However, unlike many other implementations, the default
//! client will already begin sending data in the same packet that acknowledges the reverse SYN.
//!
//! ## Accepting connections
//!
//! Accepting a connection is not unlike creating one but occurs as a reaction to an incoming
//! packet instead of proactively. This motivates deferring that decision to the user, instead of
//! remaining a question of policy within the tcp layer. You create a listening socket and with it
//! reserve one connection state for a port but it will accept only a single (successful)
//! connection attempt. The handler of the then produced [`Open`] packet needs to create more
//! reserved connection states.
//!
//! [`Open`]: struct.Open.html
//!
//! ## Deviations
//!
//! As a guide to the statemachine I had originally planned to use a paper proposing a formally
//! specified model but it is completely and utterly broken.
//!
//! > EFSM/SDL modeling of the original TCP standard (RFC793) and the Congestion Control Mechanism
//! of TCP Reno, Raid Y. Zaghal and Javed I. Khan,
//! > possibly available here: http://medianet.kent.edu/techreports/TR2005-07-22-tcp-EFSM.pdf
//!
//! Here is a list of deviations from the standard that were not noted in its introduction.  The
//! document did not ever reset `dACK`, the duplicate ack counter. We reset it whenever an ACK is
//! not a duplicate ack. Kind of obvious.
//!
//! The congestion control is (TBD). Currently likely NewReno but Westwood+ might be an option
//! since the target environment is high-throughput networks (currently). If your environment is
//! different, please provide a pull request containing an implementation.
//!
//! An incoming packet in Closed state is simply dropped if it had RST set.  Packets with RST
//! should *never* be answered with a packet with RST but the only specified answers would set that
//! flag. In fact, RFC793 is clear about this [in section Reset
//! Generation](https://tools.ietf.org/html/rfc793#page-36):
//!
//! > 1.  If the connection does not exist (CLOSED) then a reset is sent in response to any
//! incoming segment except another reset.
//!
//! A listening socket is designed to accept all connection request. That is not necessarily true
//! and we want to be indistinguishable from a closed socket else.
//!
//! Data sent in SYN packet is ignored for now but that may change in the future. If the connection
//! was initiated actively then there is virtually no difference for the handling of contained
//! segment data within the library.
use crate::wire::PayloadMut;

mod connection;
mod endpoint;
pub mod io;
mod packet;
mod socket;

mod siphash;

pub use connection::{
    AvailableBytes,
    ReceivedSegment};

pub use endpoint::{
    FourTuple,
    Slot,
    SlotKey,
    Endpoint};

pub use packet::{
    In as InPacket,
    Open,
    Raw as RawPacket,
    RecvBuf,
    SendBuf,
    Sending,
    Stray,
    UserSignals};

pub use socket::{
    Client};

// publically exposed for initialization.
pub use siphash::IsnGenerator;

/// A TCP receiver.
///
/// Processes incoming TCP traffic and automatic answers and is encouraged to generate additional
/// packets when the buffer is not needed for protocol internal messages.
pub trait Recv<P: PayloadMut> {
    /// Inspect one incoming packet buffer.
    ///
    /// The variant of `InPacket` gives more information on the available options. Note that the
    /// original packet might have been modified already if it contained no user information but
    /// necessitated a TCP specific answer.
    ///
    /// Valid received segments should be processed with the user chosen re-assembly buffer and do
    /// not affect (most of) the connection state until that point. This includes progress of the
    /// incoming data stream.
    fn receive(&mut self, frame: InPacket<P>);
}

/// A TCP sender.
///
/// Utilize raw TCP buffers to open connections or send on existing ones.
pub trait Send<P: PayloadMut> {
    /// Fill in one available packet buffer.
    ///
    /// Utilize one of the methods to create a new connection or produce packets on an already
    /// existing one. Directly modifying the endpoint is not intended and should instead be done
    /// outside the `Send` trait.
    fn send(&mut self, raw: RawPacket<P>);
}
