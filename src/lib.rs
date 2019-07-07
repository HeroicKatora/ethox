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

#[cfg(all(
    not(feature = "std"),
    not(test)))]
pub(crate) use self::managed::Vec;
#[cfg(any(
    feature = "std",
    test))]
pub(crate) use std::vec::Vec;

#[cfg(all(
    not(feature = "std"),
    not(test)))]
pub(crate) use self::managed::BTreeMap;
#[cfg(any(
    feature = "std",
    test))]
pub(crate) use std::collections::BTreeMap;
