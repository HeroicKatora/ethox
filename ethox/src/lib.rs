//! A standalone library for user-space networking and unikernels.
//!
//! ## Table of contents
//!
//! This is also a recommended reading order but feel free to skip ahead, each chapter tries to be
//! somewhat self-contained.
//!
//! 1. [Highlights](#highlights)
//! 2. [Design](#design-and-relevant-core-concepts)
//! 3. [The wire module](wire/index.html)
//!    1. [Overview of packet representations](wire/index.html#an-overview-over-packet-representations)
//!    1. [Ethernet](#TODO)
//!    1. [Arp](#TODO)
//!    1. [Ip V4/V6](layer/ip/index.html)
//!    1. [Udp](layer/udp/index.html)
//!    1. [Tcp](layer/tcp/index.html)
//!    1. [Icmp](#TODO)
//! 4. [The layers](layer/index.html)
//!    1. [Receiving](layer/index.html#receiving)
//!    1. [Sending](layer/index.html#sending)
//!    1. [Answering](layer/index.html#answering)
//!    1. [The eth layer](layer/eth/index.html)
//! 5. [Network interfaces](nic/index.html)
//!    1. [Strucuture of a NIC](#TODO)
//!    1. [Writing a nic](#TODO)
//!    1. [Included software implementations](#TODO)
//! 6. Internals
//!    1. [The managed module](managed/index.html)
//!    2. [The storage module](storage/index.html)
//!
//! ## Highlights
//!
//! The most interesting features in overview:
//!
//! * Zero-copy and bufferless TCP (re-)transmission
//! * Free choice of policy for packet queueing
//! * Optional tuntap and raw socket adapters with gigabit data rates
//!
//! Also, I'm very grateful for @whitequark's [`smoltcp`]. The overall structure may be quite
//! different but the large portions of the `wire` module wouldn't have been possible without and
//! lessons learned from studying it were integral to the design.  (Maybe also look at her other
//! projects if you have the time, very often delightful).
//!
//! [`smoltcp`]: https://github.com/m-labs/smoltcp
//!
//! ## Design and relevant core concepts
//!
//! This library handles network packets with a tree of callbacks. Don't expect builtin socket
//! interface although such adaptors may be written using the library.
//!
//! Nothing within `ethox` *ever* dynamically allocates memory (and there is no arbitrary
//! recursion). It may call user callbacks where you can *optionally* do so but it is never
//! required for operating. This may seem restrictive at first but in practice it simply means that
//! setup code will explicitely pass in preallocated memory to use instead of it being a runtime
//! choice. The philosophy of upfront, explicitely resource management also extends beyond
//! allocation. If there is any resource that connections may compete for then it tries to
//! partition them prior in a way that some minimum share is guaranteed for each or, where this is
//! not clearly possible, exposes that choice to the caller.
#![warn(missing_docs)]
#![warn(unreachable_pub)]

// tests should be able to use `std`
#![cfg_attr(all(
    not(feature = "std"),
    not(test)),
no_std)]

pub mod nic;
pub mod layer;
pub mod managed;
#[macro_use] mod macros;
pub mod storage;
pub mod time;
pub mod wire;

/// The `alloc` crate, or a replacement without feature `"std"`.
#[cfg(any(
    feature = "alloc",
    test))]
pub extern crate alloc;

#[cfg(all(
    not(feature = "alloc"),
    not(test)))]
pub use self::managed::alloc;
