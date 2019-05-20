#![cfg_attr(all(
    not(feature = "std"),
    not(test)),
no_std)]

pub mod endpoint;
pub mod nic;
mod managed;
#[macro_use] mod macros;
pub mod storage;
pub mod time;
pub mod wire;

#[cfg(all(
    not(feature = "std"),
    not(test)))]
pub(crate) use self::managed::Vec;
#[cfg(any(
    feature = "std",
    test))]
pub(crate) use std::vec::Vec;
