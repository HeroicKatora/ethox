//! The ip layer.
//!
//! While there is a possible distinction between ip4 and ip6 traffic, the layer implementation
//! tries to offer several abstractions that make this distinction less noticable. At least it
//! might some day.
// mod neighbor;
// mod route;

pub trait Receive<'a> {
}
