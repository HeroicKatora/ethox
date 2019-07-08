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

#[cfg(any(
    feature = "std",
    test))]
extern crate alloc;

#[cfg(all(
    not(feature = "std"),
    not(test)))]
pub(crate) use self::managed::alloc;
