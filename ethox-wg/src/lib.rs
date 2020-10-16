//! A `no_std` Wireguard implementation with `ethox`.
//!
//! It's not no-alloc since the underlying crypto implementation is not. If you find a library as
//! good as `ring` which provides this then we might consider switching.
#![no_std]
use core::convert::TryFrom;
use core::time::Duration;

use ethox::managed::Slice;
use ethox::time::Instant;
use ethox::wire::ip::Address;
use chacha20poly1305::{aead::{self, AeadInPlace}, XChaCha20Poly1305};

type NotSoSafeKey = aead::Key::<XChaCha20Poly1305>;

/// Static information about another Wireguard end point.
pub struct Peer {
    unbound_key: NotSoSafeKey,
    addresses: Slice<'static, Address>,
}

pub struct Client{
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

/// The nonce representation plus some common operations.
/// This CAN be cloned so be careful. The unique version is `Nonce` and that can not be cloned.
#[derive(Clone)]
struct RawNonce {
    repr: aead::Nonce::<<XChaCha20Poly1305 as AeadInPlace>::NonceSize>,
}

/// A unique nonce.
struct Nonce(RawNonce);

#[derive(Debug)]
struct UnspecifiedCryptoFailure;

pub struct CounterNonce {
    state: RawNonce,
}

/// Sliding window validator for nonces.
///
/// This is NOT a `NonceSequence`.
pub struct SlidingWindowNonce {
    base: RawNonce,
}

/// A nonce valid for the sliding window.
pub struct SlidingWindowValidatedNonce {
    nonce: Option<Nonce>,
}

impl RawNonce {
    fn new(init: u64) -> Self {
        let mut repr = [0; 24];
        repr[..8].copy_from_slice(&init.to_ne_bytes());
        RawNonce { repr: repr.into() }
    }

    fn inc(&mut self) -> Result<(), UnspecifiedCryptoFailure> {
        self.add_small(1)
    }

    fn add_small(&mut self, small: u64) -> Result<(), UnspecifiedCryptoFailure> {
        let mut carry = small;
        for chunk in self.repr.as_mut_slice().chunks_exact_mut(8) {
            let bytes: &mut [u8; 8] = TryFrom::try_from(chunk).unwrap();
            let (s, bit) = u64::from_ne_bytes(*bytes).overflowing_add(carry);
            *bytes = s.to_ne_bytes();
            carry = u64::from(bit);
        }

        if carry == 0 {
            Ok(())
        } else {
            Err(UnspecifiedCryptoFailure)
        }
    }

    /// Calculate how many inc until the `future` is reached.
    /// Returns an error when negative or too large.
    fn forward_until(&self, future: &RawNonce) -> Result<u64, UnspecifiedCryptoFailure> {
        let mut repr = future.repr;
        let mut carry = 0u64;

        // Subtract self from the future.
        for (this, chunk) in {
            self.repr.as_slice().chunks_exact(8)
                .zip(repr.as_mut_slice().chunks_exact_mut(8))
        }{
            let sub: &[u8; 8] = TryFrom::try_from(this).unwrap();
            let bytes: &mut [u8; 8] = TryFrom::try_from(chunk).unwrap();
            
            // subtract sub from bytes with carry
            let sub = u64::from_ne_bytes(*sub);
            let (s, c0) = u64::from_ne_bytes(*bytes).overflowing_sub(sub);
            let (s, c1) = s.overflowing_sub(carry);

            *bytes = s.to_ne_bytes();
            carry = u64::from(c0 | c1);
        }

        let small_bytes: &mut [u8; 8] = TryFrom::try_from(&mut repr[..8]).unwrap();
        let small = u64::from_ne_bytes(*small_bytes);
        *small_bytes = [0; 8];

        if repr.iter().any(|b| *b != 0) {
            Err(UnspecifiedCryptoFailure)
        } else {
            Ok(small)
        }
    }
}

impl CounterNonce {
    fn next_nonce(&mut self) -> Result<Nonce, UnspecifiedCryptoFailure> {
        let only_on_success = RawNonce { repr: self.state.repr };
        self.state.inc()?;
        Ok(Nonce(only_on_success))
    }
}

impl SlidingWindowNonce {
    /// Do an operation if the nonce might be valid, then invalidate the nonce on success.
    fn validate_nonce(
        &mut self,
        nonce: RawNonce,
        cb: impl FnOnce(Nonce) -> Result<(), UnspecifiedCryptoFailure>
    ) -> Result<(), UnspecifiedCryptoFailure> {

        // Validate the nonce is new.
        Err(UnspecifiedCryptoFailure)
    }
}

#[test]
fn raw_nonce_manip() {
    let mut raw = RawNonce::new(0);
    let zero = raw.clone();

    assert!(raw.inc().is_ok());
    assert!(matches!(zero.forward_until(&zero), Ok(0)));
    assert!(matches!(zero.forward_until(&raw), Ok(1)));
    assert!(raw.forward_until(&zero).is_err());

    let one = raw.clone();
    assert!(raw.add_small(u64::MAX).is_ok());
    assert!(zero.forward_until(&raw).is_err());
    assert!(matches!(one.forward_until(&raw), Ok(u64::MAX)));
    assert!(raw.forward_until(&zero).is_err());

    let other_one = RawNonce::new(1);
    assert!(matches!(one.forward_until(&other_one), Ok(0)));
    assert!(matches!(other_one.forward_until(&one), Ok(0)));


    // Can not occur in practice but okay.
    let mut last = RawNonce { repr: [0xff; 24].into() };
    assert!(last.inc().is_err());
}
