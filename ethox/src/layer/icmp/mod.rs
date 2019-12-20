//! Receiving and sending Icmp messages.
//!
//! Only supports Icmpv4 for now.
//!
//! Tuned to automate most parts of the icmp procedures *internally*. Nevertheless it will has an
//! optional interface to forward unhandled messages to a custom receiver. This is in accorance
//! with RFC1812, and extends it to unhandled packets, which states:
//!
//! > 4.3.2.1 Unknown Message Types
//!
//!   If an ICMP message of unknown type is received, it MUST be passed to
//!   the ICMP user interface (if the router has one) or silently discarded
//!   (if the router does not have one).
//! 
//! ## Icmp ping
//!
//! To answer pings there are two strategies:
//!
//! 1. Reuse the received buffer to queue a response instantly.
//! 2. Copy the payload into a temporary buffer and send a response at some later point.
//!
//! The implementation will try to reinitialize the buffer to perform a zero-copy answer, or one
//! that simply moves the payload in memory a bit. If that fails due to being unsupported for that
//! nic, it will try to store it into an internal buffer. If there is not enough space it will try
//! to forward it to the optional upper layer receiver. If that fails, the packet is discarded.
//!
//! ## Other message types
//!
//! All other message types can be received in an upper layer or are simply discarded if there is
//! no upper handler that is ready to inspect packets.
use crate::wire::Payload;

mod endpoint;
mod packet;
#[cfg(test)]
mod tests;

pub use endpoint::{
    Endpoint,
    Receiver,
    Sender,
};

pub use packet::{
    Handle,
    Init,
    In as InPacket,
    Out as OutPacket,
    Raw as RawPacket,
};


/// An ICMP receiver.
///
/// Processes incoming ICMP traffic with the option of generating automatic answers or some basic
/// customized handling.
pub trait Recv<P: Payload> {
    /// Inspect one incoming packet buffer.
    fn receive(&mut self, frame: InPacket<P>);
}

/// A ICMP sender.
///
/// Utilize raw packet buffers to send ICMP probes such as echo request or advertisements, or to
/// advise remotes of unreachable routes where `ethox` does not do so in a satisfactory manner
/// itself.
pub trait Send<P: Payload> {
    /// Fill in one available packet buffer.
    fn send(&mut self, raw: RawPacket<P>);
}
