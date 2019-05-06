#![cfg_attr(not(feature = "std"), no_std)]
pub mod endpoint;
mod managed;
#[macro_use]
mod macros;
pub mod wire;
