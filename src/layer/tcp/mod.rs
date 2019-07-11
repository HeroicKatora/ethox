//! The TCP layer abstraction.
//!
//! Offers receiver and sender implementations on top of the ip layer. Some parts differs from
//! lower layers since TCP is a connection oriented protocol but most concepts should be somewhat
//! familiar nevertheless.
//!
//! The main difference is that many incoming events *require* soliciting an answer such as an ACK
//! for received data. In effect, not all `In` packets can be turned into a `Raw` packet so send
//! arbitrary data such as opening a new connection.
//!
//! Note that they make a number of simplifying assumptions which we must refute:
//! * '2-The TCP endpoint has unlimited buffer space'
//! 
//!   This is simply not possible for an allocation free implementation. TODO: possible, just drop
//!   the packet. This would at least allow it to be used as a `Raw` packet for example for sending
//!   ones own data.
//! * A timer timeout is used to retransmit queue packets. We have no such timer but instead can
//!   utilize being called in `send` to check for that timeout. An alternate check can be deferred
//!   to user code at any point where a send buffer (i.e. a `Raw` packet) is available. The raw
//!   buffer is returned if it was not consumed.
//! * Data can sometimes be piggy-backed on some packets that contain status communication. Note
//!   however that for some networks there is a cost associated with large packet, mostly as higher
//!   drop rates. This may be the case due to badly configured buffers but also congestion avoidance
//!   mechanisms.
//!
//! ## Structure
//!
//! The main functionality of the 'endpoint' structure of this layer is storing the connection
//! states, unlike other layers which mostly store configuration options.
//!
//! Unlike standard stacks where state and user must be assumed to be in different protection
//! domains and which manage their state opaquely, it poses no problem for this library to allow
//! inspection of internal state or modification (by the user) beyond the transitions mandated in
//! the protocol standard.
//!
//! ## Creating a connection
//!
//! TODO
//!
//! ## Accepting connections
//!
//! Accepting a connection is not unlike creating one but occurs as a reaction to an incoming
//! packet instead of proactively. This motivates deferring that decision to the user, instead of
//! remaining a question of policy within the tcp layer.
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
//! SYN packet may contain data. 
//!

mod connection;
mod endpoint;
mod packet;

mod siphash;

pub use endpoint::{
    Slot,
    SlotKey,
    Endpoint};

// publically exposed for initialization.
pub use siphash::IsnGenerator;
