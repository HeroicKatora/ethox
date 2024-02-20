//! The ethernet layer.
//!
//! This is tasked with decoding the framed ethernet data that the physical device deals with, and
//! putting upper layer data into an ethernet framing. This is conceptually and practically simply
//! an implementation of the ideas outlined in the [generic layer documentation][layer]. The state
//! and logic within the ethernet endpoint is tiny compared to other layers.
//!
//! [layer]: ../index.html
use crate::wire::{Payload, pretty_print};
#[cfg(feature = "std")]
use crate::wire::{pretty_print::Formatter, PrettyPrinter, ethernet};

mod endpoint;
mod packet;

pub use endpoint::{
    Endpoint,
    Receiver,
    Sender,
};

pub use packet::{
    Controller,
    Init,
    In as InPacket,
    Out as OutPacket,
    Raw as RawPacket,
};

/// A ethernet receiver.
///
/// Processes incoming ethernet frames and automatic answers and is encouraged to generate
/// additional packets when the buffer is not needed for protocol internal messages.
pub trait Recv<P: Payload> {
    /// Inspect one incoming, valid ethernet frame in a packet buffer.
    fn receive(&mut self, frame: InPacket<P>);
}

/// An ethernet sender.
///
/// Utilize raw packet buffers to generate ethernet frames with control over options, flags,
/// encapsulated upper layer payload and other extensions.
pub trait Send<P: Payload> {
    /// Fill in one available packet buffer.
    ///
    /// Use the `Handle`'s [`src_addr`] method to find the hardware address identifying this device
    /// and use it during initialization of the frame within the buffer.
    ///
    /// [`src_addr`]: struct.Handle.html#method.src_addr
    fn send(&mut self, raw: RawPacket<P>);
}

/// Pretty print all frames that are received.
///
/// Available only on `std` because it prints to standard out.
#[cfg(feature = "std")]
impl<P: Payload> Recv<P> for Formatter<ethernet::frame> {
    fn receive(&mut self, frame: InPacket<P>) {
        let printer = PrettyPrinter::<ethernet::frame>::print(&frame.frame);
        eprintln!("{}", printer);
    }
}

#[cfg(feature = "std")]
impl<P: Payload, I> Recv<P> for pretty_print::FormatWith<I, ethernet::frame>
    where I: Recv<P>
{
    fn receive(&mut self, frame: InPacket<P>) {
        let printer = PrettyPrinter::<ethernet::frame>::print(&frame.frame);
        eprintln!("{}", printer);
        self.inner.receive(frame);
    }
}

#[cfg(feature = "std")]
impl<P: Payload, I> Send<P> for pretty_print::FormatWith<I, ethernet::frame>
    where I: Send<P>
{
    fn send(&mut self, mut frame: RawPacket<P>) {
        self.inner.send(RawPacket {
            control: frame.control.borrow_mut(),
            payload: frame.payload,
        });

        match frame.control.nic_handle.is_queued() {
            Ok(false) => {},
            Ok(true) => {
                let printer = PrettyPrinter::<ethernet::frame>::new("-> ", frame.payload.payload());
                eprintln!("{}", printer);
            }
            Err(_) => {
                let printer = PrettyPrinter::<ethernet::frame>::new("? ", frame.payload.payload());
                eprintln!("{}", printer);
            }
        }
    }
}

impl<P: Payload, E> Recv<P> for &'_ mut E
    where E: Recv<P>
{
    fn receive(&mut self, frame: InPacket<P>) {
        (**self).receive(frame)
    }
}

impl<P: Payload, E> Send<P> for &'_ mut E
    where E: Send<P>
{
    fn send(&mut self, frame: RawPacket<P>) {
        (**self).send(frame)
    }
}
