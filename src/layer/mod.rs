//! The process logic of protocol layers.
//!
//! ## Layering
//!
//! Each protocol layer is split into two parts; the packet logic contained in `wire` and the
//! processing part in this module. An endpoint represents the local state of a protocol. This
//! state can be used to process packets of that layer. The state is open to modifications as part
//! of a user program while processing does not take place, similar to reconfiguration on the OS
//! level with utilities such as `arp`, `ifconfig`, etc.
//!
//! ## Receiving
//!
//! Many layer implementations process packets by routing them to layers conceptually above them.
//! This functionality is provided via abstract traits accepting the processed packets of that
//! layer which contain the payload to-be-consumed in the layer above. The encapsulation can be
//! removed if the upper layer does not require any knowledge of the layer below. However, it must
//! be preserved when one wants to use the lower layer for device or protocol specific actions.
//!
//! ## Sending
//!
//! [WIP]
//!
//! ## In-depth packet representation
//!
//! These are the design goals:
//! * Packet encapsulations may have internal invariants. In particular, the design must not depend
//!   on particular implementation of `AsRef<[u8]> + AsMut<[u8]>` to allow this. Thus, the
//!   processing pipeline must be able to store a reference to the packet content whose lifetime
//!   does not restrict access to other relevant data elsewhere. This needs to be cleanly
//!   separated.
//! * Minimize the number of 'callback' arguments, and avoid double dispatch. Single dispatch is
//!   okay, and the arguments that it receives should provide all necessary methods to manipulate
//!   the content.
//! * Minimize the library magic. As many mechanisms as possible should be open to customization.
//!   This includes the protocol receptor implementations but not the core structures of data
//!   reprsentations.
//!
//! Only interpreting to a packet's content by referencing the memory region in which it is
//! contained would require reinterpreting all layers on every mutable access at least.
//! Fortunately, there are two classes of types for which we can trust trait implementations
//! sufficiently well: types local to the crate; and types in the standard library. Thus, the
//! actual representation of parsed packet data needs to be separated from the additional data
//! provided by each layer endpoint (which should be implementable by a user as well). The
//! functionality that provides the packet representation is called `Payload` and `PayloadMut`.

pub mod arp;
pub mod eth;
pub mod icmp;
pub mod ip;
pub mod udp;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    /// The operation was not permitted.
    ///
    /// Returned when the device, endpoint, receiver or sender does not allow or implement an
    /// operation.
    Illegal,

    /// Not enough space for the requested packet.
    ///
    /// May also be returned when trying to resize a packet but the requested length can not be
    /// fulfilled. In contrast to `Illegal` this would signal that a smaller size may be possible.
    BadSize,

    /// Unable to find a route towards the destination address.
    Unreachable,

    /// The action could not be completed because there were not enough resources.
    ///
    /// The main difference towards `Illegal` is that implies that it would have been legal with
    /// more resources. If you get this return value you may want to perform manual cleanup if
    /// possible or gargabe collect.
    Exhausted,
    // TODO
}

/// A standard wrapper for a function implementing receive or send traits.
///
/// Keeps the type alias overhead low by providing a single wrapper type that implements the send
/// and receive traits for all layers, where applicable.
pub struct FnHandler<F>(pub F);

/// Can convert from a wire error.
///
/// This indicates some layer tried to operate on a packet but failed.
impl From<crate::wire::Error> for Error {
    fn from(_: crate::wire::Error) -> Self {
        Error::Illegal
    }
}

/// Can convert from a payload error.
///
/// One common cause is failure to resize the buffer to the necessary size.
impl From<crate::wire::PayloadError> for Error {
    fn from(err: crate::wire::PayloadError) -> Self {
        use crate::wire::PayloadError;
        match err {
            PayloadError::BadSize => Error::BadSize,
        }
    }
}
