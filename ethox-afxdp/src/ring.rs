//! A SPSC ring for owned buffers.
//!
//! The receiver never (safely) accepts owned buffers by value, as the buffers are bound to a
//! particular ring and it would be unsound to use them on others.
//! 
//! This is mostly a copy of the XDP/io-uring design, there's nothing really to improve, is there?
//! The only difference is that the memory region is explicitly made up as an array of atomics.
use core::sync::atomic::AtomicU32;
use alloc::sync::Arc;

pub struct Producer {
    mask: u32,
    size: u32,
    /// The producer register. Note: refers to within the `area`.
    producer: &'static AtomicU32,
    /// The consumer register. Note: refers to within the `area`.
    consumer: &'static AtomicU32,
    /// All allocated memory for this ring.
    area: Arc<[AtomicU32]>,
}

pub struct Consumer {
    area: Arc<[AtomicU32]>,
}
