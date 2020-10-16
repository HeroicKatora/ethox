//! A `no_std` Wireguard implementation with `ethox`.
//!
//! It's not no-alloc since the underlying crypto implementation is not. If you find a library as
//! good as `ring` which provides this then we might consider switching.
#![no_std]
use core::time::Duration;

use ethox::time::Instant;
use chacha20poly1305::{aead::{self, AeadInPlace}, XChaCha20Poly1305};

pub struct Peer {
    /// Send empty packet if we haven't heard for a while.
    keepalive: Duration,
    /// The last time we heard from the peer.
    last_alive: Instant,
    /// The constant rekey timeout.
    /// If keepalive times out then we initiate rekey handshake.
    rekey_timeout: Duration,
    /// The REJECT_AFTER_TIME constant for the peer.
    reject_after_time: Duration,
    /// The REKEY_AFTER_MESSAGES constant.
    /// After this number of packets we initiate a new handshake.
    rekey_after_messages: u32,
    /// The number of message we sent without rekey according to `rekey_after_messages`.
    /// Begin to drop packets when this is greater than `rekey_after_messages`.
    messages_without_rekey: u32,
    /// Timeout until we rekey independent of messages or keep-alive.
    rekey_after_time: Duration,
    /// The last timestamp when we rekeyed.
    last_rekey_time: Instant,
    /// The greatest received timestamp for this peer.
    tai64n: u64,
}

/// State of one handshake.
///
/// Retried after `REKEY_TIMEOUT + jitter` where jitter `[0; 330ms]`.
pub struct Handshake {
    /// The constant rekey timeout.
    rekey_timeout: Duration,
    /// Currently chosen jitter duration.
    jitter: Duration,
}

type Nonce = aead::Nonce::<<XChaCha20Poly1305 as AeadInPlace>::NonceSize>;

pub struct CreatedNonce {
}

/// Sliding window validator for nonces.
///
/// This is NOT a `NonceSequence`.
pub struct SlidingWindowNonce {
}

/// A nonce valid for the sliding window.
pub struct SlidingWindowValidatedNonce {
    nonce: Option<Nonce>,
}
