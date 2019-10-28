//! A standalone library for user-space networking and unikernels.
//!
//! # Highlights
//!
//! The most interesting features in overview:
//!
//! * Zero-copy and bufferless TCP (re-)transmission
//! * Free choice of policy for packet queueing
//! * Optional tuntap and raw socket adapters with gigabit data rates
//!
//! # Design and relevant core concepts
//!
//! This library handles network packets with a tree of callbacks. Don't expect builtin socket
//! interface although such adaptors may be written using the library. The design was influenced by
//! [`smoltcp`] and some code is borrowed from it.
//!
//! Nothing within `ethox` *ever* dynamically allocates memory (and there is no arbitrary
//! recursion). It may call user callbacks where you can *optionally* do so but it is never
//! required for operating. This may seem restrictive at first but in practice it simply means that
//! setup code will explicitely pass in preallocated memory to use instead of it being a runtime
//! choice. The philosophy of upfront, explicitely resource management also extends beyond
//! allocation. If there is any resource that connections may compete for then it tries to
//! partition them prior in a way that some minimum share is guaranteed for each or, where this is
//! not clearly possible, exposes that choice to the caller.
//!
//! [`smoltcp`]: https://github.com/m-labs/smoltcp
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
