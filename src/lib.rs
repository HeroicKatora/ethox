#![cfg_attr(all(
    not(feature = "std"),
    not(test)),
no_std)]

pub mod endpoint;
pub mod nic;
mod managed;
#[macro_use]
mod macros;
pub mod storage;
pub mod wire;
