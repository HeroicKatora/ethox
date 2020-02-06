/*! Low-level packet access and construction.

# An overview over packet representations

The `wire` module deals with the packet *representation*. It provides three levels of
functionality.

 * First, it provides functions to extract fields from sequences of octets, and to insert fields
   into sequences of octets. This happens in the lowercase structures e.g.  [`ethernet_frame`] or
   [`udp_packet`] [^tcp].
 * Second, it provides a compact, high-level representation of header data that can be created from
   parsing and emitted into a sequence of octets. This happens through the `Repr` family of structs
   and enums, e.g. [`ArpRepr`] or [`Ipv4Repr`].
 * Third, it provides an type wrapper around sequences of octets valid as a particular packet
   format which potentially owns its data. This can memoize parts of the layout, avoiding
   re-calculating it on every access. While this restricts mutability of header data, fixed-length
   checksum fields and the payload can still be accessed normally. This happens in the uppercase
   Frame or Packet family of structs, e.g. [`ArpPacket`] or [`UdpPacket`].

[`ethernet_frame`]: struct.ethernet_frame.html
[`udp_packet`]: struct.udp_packet.html
[`ArpRepr`]: enum.ArpRepr.html
[`Ipv4Repr`]: struct.Ipv4Repr.html
[`ArpPacket`]: struct.ArpPacket.html
[`UdpPacket`]: struct.UdpPacket.html

[^tcp]: The TCP structures differ since I haven't gotten around to reworking them. It does not have
a dynamically sized byte wrapper so its `Packet` implements this functionality as well but come
with all downsides. In particular, its accessors may panic.

An important part is also the underlying trait for byte containers, [`Payload`] and [`PayloadMut`].
None of the standard reference traits accurately captures the relationship of a framing outer
packet with its payload. It should be the case that the payload content changes only when accessed
directly and changing its length should be possible. These two traits model such a relationship,
providing a few methods to efficiently request layout changes of the payload from the container.
This makes it possible to recursively parse packets while being able to resize the innermost packet
or to insert additional data into an intermediate layer without mutating the payload.

[`Payload`]: trait.Payload.html
[`PayloadMut`]: trait.Payload.html

The `packet` family of data structures guarantees that, if the `packet::check_len()` method
returned `Ok(())`, then no field accessor or setter method will panic; however, the guarantee only
hold while specific fields are mutated, which are listed in the documentation for the specific
packet.

The owning `Packet` family makes a stronger guarantee. It only exposes fields for which mutation
will not *cause* panics (some panics are still possible, read on), as long as `Packet::new_checked`
constructor was used or the `new_unchecked` constructor with previously parsed data. Where such a
mutation causes the layout to change (i.e. payload length) the underlying container is first asked
to perform the necessary reframing and then dependent fields and offsets are updated. Note that
this ties panicking to the container: A misbehaving implementation that implements the `PayloadMut`
trait incorrectly or a fallible allocation could still cause panics.

The `packet::new_unchecked` method is a shorthand for combining `new_unchecked` and `check_len`
while the `Packet::new_checked` method is a shorthand for a combination of `Packet::new_unchecked`
and `Repr::parse`. When parsing untrusted input, it is *necessary* to use either of the checked
methods; so long as the buffer is not modified, no accessor will fail.  When emitting output,
though, it is *incorrect* to use `Packet::new_checked()`; the length check is likely to succeed on
a zeroed buffer, but fail on a buffer filled with data from a previous packet, such as when reusing
buffers, resulting in nondeterministic panics with some network devices but not others.  The buffer
length for emission is often calculated by the `Repr` struct but not in general provided by the
`Packet` layer.

In the `Repr` family of data structures, the `Repr::parse()` method never panics and the
`Repr::emit()` method never panics as long as the underlying buffer is exactly `Repr::buffer_len()`
octets long if provided.

# Examples

To emit an IP packet header into an octet buffer, and then parse it back:

```rust
#
# {
use ethox::wire::{ip::v4, Checksum, ip::Protocol};
let repr = v4::Repr {
    src_addr:    v4::Address::new(10, 0, 0, 1),
    dst_addr:    v4::Address::new(10, 0, 0, 2),
    protocol:    Protocol::Tcp,
    payload_len: 10,
    hop_limit:   64
};
let mut buffer = vec![0; repr.buffer_len() + repr.payload_len];
{ // emission
    let packet = v4::packet::new_unchecked_mut(&mut buffer);
    repr.emit(packet, Checksum::Manual);
}
{ // parsing
    let packet = v4::packet::new_checked(&buffer)
        .expect("truncated packet");
    let parsed = v4::Repr::parse(packet, Checksum::Manual)
        .expect("malformed packet");
    assert_eq!(repr, parsed);
}
# }
```
*/
// Copyright (C) 2016 whitequark@whitequark.org
// Copyright (C) 2019 Andreas Molzer <andreas.molzer@tum.de>
//
// in large parts from `smoltcp` originally distributed under 0-clause BSD
//
// Applies to files in this folder unless otherwise noted. These are:
// * `arp.rs`
// * `dhcpv4.rs`
// * `error.rs`
// * `ethernet.rs`
// * `icmp.rs`
// * `icmpv4.rs`
// * `icmpv6.rs`
// * `igmp.rs`
// * `ip.rs`
// * `ipv4.rs`
// * `ipv6fragment.rs`
// * `ipv6hopbyhop.rs`
// * `ipv6option.rs`
// * `ipv6routing.rs`
// * `ipv6.rs`
// * `mld.rs`
// * `mod.rs` (this file)
// * `ndiscoption.rs`
// * `ndisc.rs`
// * `pretty_print.rs`
// * `tcp.rs`
// * `udp.rs`

// FIXME: Most fields should be self-explanatory and there is the general guide but enable once the
// other issues have been resolved.
#![allow(missing_docs)]

mod field {
    pub(crate) type Field = ::core::ops::Range<usize>;
    pub(crate) type Rest  = ::core::ops::RangeFrom<usize>;
}

pub mod pretty_print;

#[path = "."]
mod raw {
    pub(crate) mod ethernet;
    pub(crate) mod arp;
    pub(crate) mod ip;
    pub(crate) mod ipv4;
    pub(crate) mod ipv6;
    pub(crate) mod ipv6option;
    pub(crate) mod ipv6hopbyhop;
    pub(crate) mod ipv6fragment;
    pub(crate) mod ipv6routing;
    pub(crate) mod icmpv4;
    // mod icmpv6;
    // mod icmp;
    // #[cfg(feature = "proto-igmp")]
    // mod igmp;
    // mod ndisc;
    // mod ndiscoption;
    // mod mld;
    pub(crate) mod udp;
    pub(crate) mod tcp;
}

// mod ethernet;
mod error;
// pub(crate) mod dhcpv4;

#[path = "payload.rs"]
mod payload_impl;
mod payload_ext;

/// Describes how to handle checksums.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Checksum {
    /// Checksum must be computed or checked manually.
    Manual,

    /// The checksum field is filled or checked by the NIC.
    Ignored,
}

pub use self::payload_impl::{Reframe, Payload, PayloadMut, Error as PayloadError, payload};
pub use self::payload_ext::{ReframePayload, PayloadMutExt};

/// The result type of a reframing operation on [`PayloadMut`].
///
/// [`PayloadMut`]: trait.PayloadMut.html
pub type PayloadResult<T> = core::result::Result<T, PayloadError>;

pub use self::pretty_print::PrettyPrinter;

// Public re-exports with the wanted structure.

pub use self::error::{Error, Result};

pub mod ethernet {
    pub use super::raw::ethernet::{
        ethernet as frame,
        EtherType,
        Address,
        Frame,
        Repr,
    };
}

pub mod arp {
    pub use super::raw::arp::{
        arp as packet,
        Hardware,
        Operation,
        Packet,
        Repr,
    };
}

pub mod ip {
    pub use super::raw::ip::{
        Version,
        Protocol,
        Address,
        Endpoint,
        Repr,
        Cidr,
        Subnet,
    };

    pub mod v4 {
        pub use super::super::raw::ipv4::{
            ipv4 as packet,
            Address,
            Packet,
            Repr,
            Cidr,
            Subnet,
            MIN_MTU,
        };
    }

    pub mod v6 {
        pub use super::super::raw::ipv6::{
            ipv6 as packet,
            Address,
            InterfaceId,
            Packet,
            Repr,
            Cidr,
            Subnet,
            MIN_MTU,
        };

        pub mod options {
            pub use super::super::super::raw::ipv6option::{
                Ipv6Option as Option,
                Repr,
                Type,
                FailureType,
            };
        }

        pub mod hopbyhop {
            pub use super::super::super::raw::ipv6hopbyhop::{
                Header,
                Repr,
            };
        }

        pub mod fragment {
            pub use super::super::super::raw::ipv6fragment::{
                Header,
                Repr,
            };
        }

        pub mod routing {
            pub use super::super::super::raw::ipv6routing::{
                Header,
                Repr,
            };
        }
    }
}

pub mod icmpv4 {
    pub use super::raw::icmpv4::{
        icmpv4 as packet,
        Packet,
        Repr,
        Message,
        DstUnreachable,
        Redirect,
        TimeExceeded,
        ParamProblem,
    };
}

/*
#[cfg(feature = "proto-igmp")]
pub use self::igmp::{
    Packet as IgmpPacket,
    Repr as IgmpRepr,
    IgmpVersion};

pub use self::icmpv6::{
    Message as Icmpv6Message,
    DstUnreachable as Icmpv6DstUnreachable,
    TimeExceeded as Icmpv6TimeExceeded,
    ParamProblem as Icmpv6ParamProblem,
    Packet as Icmpv6Packet,
    Repr as Icmpv6Repr};

pub use self::icmp::Repr as IcmpRepr;
*/

/*
pub use self::ndisc::{
    Repr as NdiscRepr,
    RouterFlags as NdiscRouterFlags,
    NeighborFlags as NdiscNeighborFlags};

pub use self::ndiscoption::{
    NdiscOption,
    Repr as NdiscOptionRepr,
    Type as NdiscOptionType,
    PrefixInformation as NdiscPrefixInformation,
    RedirectedHeader as NdiscRedirectedHeader,
    PrefixInfoFlags as NdiscPrefixInfoFlags};
*/

/*
pub use self::mld::{
    AddressRecord as MldAddressRecord,
    Repr as MldRepr};
*/

pub mod udp {
    pub use super::raw::udp::{
        udp as packet,
        Packet,
        Repr,
        Checksum,
    };
}

pub mod tcp {
    pub use super::raw::tcp::{
        Packet,
        Repr,
        Checksum,
        SeqNumber,
        TcpOption as Option,
        Flags,
    };
}

#[cfg(feature = "proto-dhcpv4")]
pub use self::dhcpv4::{
    Packet as DhcpPacket,
    Repr as DhcpRepr,
    MessageType as DhcpMessageType};

impl Checksum {
    /// Check if a checksum should be calculated by the library.
    ///
    /// Otherwise it is ignored due to the assumption that it was offloaded or is otherwise
    /// undesirable to check.
    pub fn manual(self) -> bool {
        match self {
            Checksum::Manual => true,
            Checksum::Ignored => false,
        }
    }
}
