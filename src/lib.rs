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
    feature = "std",
    test))]
pub extern crate alloc;

#[cfg(all(
    not(feature = "std"),
    not(test)))]
pub use self::managed::alloc;
