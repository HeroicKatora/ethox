//! A `no_std` Wireguard implementation with `ethox`.
//!
//! It's not no-alloc since the underlying crypto implementation is not. If you find a library as
//! good as `ring` which provides this then we might consider switching.
#![no_std]
extern crate alloc;

/// Maps the libraries to the crypto primitives defined in the Whitepaper.
mod crypto;
/// Defines the wire formats for packets.
mod wire;
/// Defines the ethox-layer for the handler.
mod layer;

use core::convert::TryFrom;
use core::time::Duration;

use ethox::managed::Slice;
use ethox::time::Instant;
use ethox::wire::ip::Address;
use chacha20poly1305::{aead::{self, AeadInPlace}, ChaCha20Poly1305, XChaCha20Poly1305};
use x25519_dalek::{PublicKey, StaticSecret};

/// A key for which we haven't decided if its sealing, unsealing, or raw key material.
///
/// In particular it might be dangerous to use this with a new nonce sequence if we don't ensure
/// that the key is immediately discarded afterwards.
type NotSoSafeKey = aead::Key::<XChaCha20Poly1305>;

pub struct This {
    private: StaticSecret,
    public: PublicKey,
    system: crypto::System,
}

/// A pre-calculation for a handshake to a peer.
pub struct PreHandshake {
    initiator_key: NotSoSafeKey,
    initiator_hash: [u8; 32],
    mac1_key: NotSoSafeKey,
    initiator_public: PublicKey,
    peer_public: PublicKey,
    /// Optional preshared key.
    pre_shared_key: [u8; 32],
}

/// The state after a handshake init.
///
/// Construct it by creating a message, or by unsealing one to us.
pub struct PostInitHandshake {
    /// The rolling key for the hash observing the handshake.
    initiator_key: NotSoSafeKey,
    /// The current hash after the init message.
    initiator_hash: [u8; 32],
    /// The ephemeral public key of the initiator.
    initiator_public: PublicKey,
    /// The ephemeral public key.
    ephemeral_public: PublicKey,
    /// The ephemeral private key if we created the handshake.
    ephemeral_private: Option<StaticSecret>,
    pre_shared_key_q: [u8; 32],
}

/// The state after a handshake response.
///
/// Construct it by responding to a `PostInitHandshake`, or by unsealing a response.
pub struct PostResponseHandshake {
    /// The rolling key for the hash observing the handshake.
    initiator_send: NotSoSafeKey,
    /// The current hash after the init message.
    initiator_recv: NotSoSafeKey,
    /// The rolling key for the hash observing the handshake.
    responder_send: NotSoSafeKey,
    /// The current hash after the response message.
    responder_recv: NotSoSafeKey,
    /// The final chaining hash.
    chaining_hash: [u8; 32],
}

/// Static information about another Wireguard end point.
pub struct Peer {
    public: PublicKey,
    addresses: Slice<'static, Address>,
    /// Precomputed derived keys for populating mac1 in cookie requests.
    labelled_mac1_key: NotSoSafeKey,
    /// Precomputed derived keys for populating mac1 in cookie replies.
    labelled_cookie_key: NotSoSafeKey,
    pre_shared_key: [u8; 32],
}

/// Non crypto graphic state for a connection.
pub struct Client {
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

type XChaCha20Poly1305Nonce = aead::Nonce::<<XChaCha20Poly1305 as AeadInPlace>::NonceSize>;
type ChaCha20Poly1305Nonce = aead::Nonce::<<ChaCha20Poly1305 as AeadInPlace>::NonceSize>;

/// The nonce representation plus some common operations.
/// This CAN be cloned so be careful. The unique version is `Nonce` and that can not be cloned.
#[derive(Clone)]
struct RawNonce {
    repr: aead::Nonce::<<XChaCha20Poly1305 as AeadInPlace>::NonceSize>,
}

/// A unique nonce.
struct Nonce(RawNonce);

#[derive(Debug)]
pub struct UnspecifiedCryptoFailure;

pub struct CounterNonce {
    state: RawNonce,
}

/// Sliding window validator for nonces.
///
/// This is NOT a `NonceSequence`.
pub struct SlidingWindowNonce {
    latest_seen_nonce: RawNonce,
    words: [u64; Self::WORD_COUNT],
}

/// A nonce valid for the sliding window.
pub struct SlidingWindowValidatedNonce {
    nonce: Option<Nonce>,
}

impl RawNonce {
    fn new(init: u64) -> Self {
        let mut repr = [0; 24];
        repr[16..].copy_from_slice(&init.to_ne_bytes());
        RawNonce { repr: repr.into() }
    }

    fn as_xaead_nonce(&self) -> &XChaCha20Poly1305Nonce {
        &self.repr
    }

    fn as_aead_nonce(&self) -> &ChaCha20Poly1305Nonce {
        ChaCha20Poly1305Nonce::from_slice(&self.repr[12..])
    }

    fn inc(&mut self) -> Result<(), UnspecifiedCryptoFailure> {
        self.add_small(1)
    }

    fn add_small(&mut self, small: u64) -> Result<(), UnspecifiedCryptoFailure> {
        let mut carry = small;
        let mut repr = self.repr;

        for chunk in repr.as_mut_slice().chunks_exact_mut(8).rev() {
            let bytes: &mut [u8; 8] = TryFrom::try_from(chunk).unwrap();
            let (s, bit) = u64::from_le_bytes(*bytes).overflowing_add(carry);
            *bytes = s.to_le_bytes();
            carry = u64::from(bit);
        }

        if carry == 0 {
            self.repr = repr;
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
            self.repr.as_slice().chunks_exact(8).rev()
                .zip(repr.as_mut_slice().chunks_exact_mut(8).rev())
        }{
            let sub: &[u8; 8] = TryFrom::try_from(this).unwrap();
            let bytes: &mut [u8; 8] = TryFrom::try_from(chunk).unwrap();
            
            // subtract sub from bytes with carry
            let sub = u64::from_le_bytes(*sub);
            let (s, c0) = u64::from_le_bytes(*bytes).overflowing_sub(sub);
            let (s, c1) = s.overflowing_sub(carry);

            *bytes = s.to_le_bytes();
            carry = u64::from(c0 | c1);
        }

        let small_bytes: &mut [u8; 8] = TryFrom::try_from(&mut repr[16..]).unwrap();
        let small = u64::from_le_bytes(*small_bytes);

        *small_bytes = [0; 8];
        if repr.iter().any(|b| *b != 0) || carry != 0 {
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

impl Default for CounterNonce {
    fn default() -> CounterNonce {
        CounterNonce {
            state: RawNonce::new(0),
        }
    }
}

impl Nonce {
    fn as_xaead_nonce(&self) -> &XChaCha20Poly1305Nonce {
        self.0.as_xaead_nonce()
    }

    fn as_aead_nonce(&self) -> &ChaCha20Poly1305Nonce {
        self.0.as_aead_nonce()
    }
}

impl Default for SlidingWindowNonce {
    fn default() -> Self {
        // Requires that it is valid to round-trip those constants.
        // This catches mistakes as it makes it an effective safety invariant of the type.
        assert_eq!(Self::WORD_COUNT as u64 as usize, Self::WORD_COUNT);
        assert_eq!(Self::WORD_BITS as u64 as usize, Self::WORD_BITS);
        assert_eq!(Self::BITS as u64 as usize, Self::BITS);

        SlidingWindowNonce {
            latest_seen_nonce: RawNonce::new(0),
            words: [0; Self::WORD_COUNT],
        }
    }
}

impl SlidingWindowNonce {
    const WORD_COUNT: usize = 16;
    const WORD_BITS: usize = 64;
    const BITS: usize = Self::WORD_BITS*Self::WORD_COUNT;

    /// Do an operation if the nonce might be valid, then invalidate the nonce on success.
    fn validate_nonce(
        &mut self,
        nonce: RawNonce,
        message_validator: impl FnOnce(Nonce) -> Result<(), UnspecifiedCryptoFailure>
    ) -> Result<(), UnspecifiedCryptoFailure> {
        if let Ok(by_n) = nonce.forward_until(&self.latest_seen_nonce) {
            // When the nonce is not in the future..
            // Let's see if it is inside the window.
            let (word, bit) = self.word_and_bit_of(by_n)?;
            // And when it is, it must be unused.
            // Note that initial even the `latest_seen_nonce = 0` is unused.
            self.require_empty_relative(word, bit)?;
            // Okay, is a unique nonce. Now, is it a valid message?
            message_validator(Nonce(nonce.clone()))?;
            // Invalidate the nonce, no update of latest_seen_nonce.
            self.strike_out_relative(word, bit);
            Ok(())
        } else if let Ok(n) = self.latest_seen_nonce.forward_until(&nonce) {
            assert!(n > 0, "None can not be last seen"); // Was handled before in `if`.
            // The nonce is in the future.
            // This is always valid.
            message_validator(Nonce(nonce.clone()))?;
            // Okay, now update the latest_seen_nonce.
            self.slide_window(n);
            self.latest_seen_nonce = nonce;
            // And remove the just used none.
            self.strike_out_relative(0, 0);
            Ok(())
        } else {
            // Validate the nonce is new.
            Err(UnspecifiedCryptoFailure)
        }
    }

    fn window_size(&self) -> u64 {
        Self::BITS as u64
    }

    fn slide_window(&mut self, by: u64) {
        if by >= self.window_size() {
            return self.words.iter_mut().for_each(|b| *b = 0);
        }

        let by = by as usize;
        let full_words = by / Self::WORD_BITS;
        let bits = (by % Self::WORD_BITS) as u64;
        // First shift everything by full bytes, filling zeros.
        self.words[..].rotate_right(full_words);
        self.words[..full_words].iter_mut().for_each(|b| *b = 0);
        // Then shift the bits, new bits enter from the bottom.
        self.words[full_words..]
            .iter_mut()
            .fold(0u64, |next_bits, word| {
                let temp = *word;
                *word = (temp << bits) | next_bits;
                // Spiritually, temp >> (Self::WORD_BITS as u64 - bits)
                // But for bits == 0 we can not do that.
                // However, we shift by at least one.
                (temp >> 1) >> (Self::WORD_BITS as u64 - bits - 1)
            });
    }

    fn word_and_bit_of(&self, backwards: u64) -> Result<(usize, usize), UnspecifiedCryptoFailure> {
        if backwards >= self.window_size() {
            Err(UnspecifiedCryptoFailure)
        } else {
            let offset = backwards as usize;
            Ok((offset / Self::WORD_BITS, offset % Self::WORD_BITS))
        }
    }

    fn require_empty_relative(&self, word: usize, bit: usize) -> Result<(), UnspecifiedCryptoFailure> {
        assert!(word < Self::WORD_COUNT);
        assert!(bit < Self::WORD_BITS);
        if self.words[word] & 1 << bit == 0 {
            Ok(())
        } else {
            Err(UnspecifiedCryptoFailure)
        }
    }

    fn strike_out_relative(&mut self, word: usize, bit: usize) {
        assert!(word < Self::WORD_COUNT);
        assert!(bit < Self::WORD_BITS);
        self.words[word] |= 1 << bit;
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
    // On the definiton of Aead:
    // > [..] with its nonce being composed of 32 bits of zeros followed by the 64-bit
    // little-endian value of counter.
    assert_eq!(one.as_aead_nonce().as_slice(), &[0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]);
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
    assert!(last.inc().is_err());
    assert!(last.forward_until(&zero).is_err());
}

#[test]
fn sliding_window() {
    let mut window = SlidingWindowNonce::default();
    assert!(window.require_empty_relative(0, 0).is_ok());
    window.strike_out_relative(0, 1);
    assert!(window.require_empty_relative(0, 0).is_ok());
    assert!(window.require_empty_relative(0, 1).is_err());
    window.slide_window(2);
    assert!(window.require_empty_relative(0, 1).is_ok());
    assert!(window.require_empty_relative(0, 3).is_err());
    window.slide_window(SlidingWindowNonce::WORD_BITS as u64);
    assert!(window.require_empty_relative(0, 3).is_ok());
    assert!(window.require_empty_relative(1, 3).is_err());
    window.slide_window(SlidingWindowNonce::WORD_BITS as u64 - 3);
    assert!(window.require_empty_relative(1, 3).is_ok());
    assert!(window.require_empty_relative(2, 0).is_err());
}

#[test]
fn sliding_validation() {
    let mut window = SlidingWindowNonce::default();

    // A function that says the mac was good.
    let ok = |_| Ok(());
    // A function that says the message was not authenticated.
    let err = |_| Err(UnspecifiedCryptoFailure);
    // A function that tests the sliding window filtered correctly.
    let must_not_be_called = |nonce: Nonce| panic!("Invalid nonce passed {:?}", nonce.0.repr);

    // Check: we can initialize the sequence by starting at 0.
    assert!(window.validate_nonce(RawNonce::new(0), &err).is_err());
    assert!(window.validate_nonce(RawNonce::new(0), &ok).is_ok());
    assert!(window.require_empty_relative(0, 0).is_err());
    assert!(window.validate_nonce(RawNonce::new(0), &must_not_be_called).is_err());

    // Check: we can use the next in sequence.
    assert!(window.validate_nonce(RawNonce::new(1), &ok).is_ok());
    assert!(window.require_empty_relative(0, 0).is_err());
    assert!(window.require_empty_relative(0, 1).is_err());
    assert!(window.validate_nonce(RawNonce::new(0), &must_not_be_called).is_err());
    assert!(window.validate_nonce(RawNonce::new(1), &must_not_be_called).is_err());

    // Check: we can skip forward.
    assert!(window.validate_nonce(RawNonce::new(64), &ok).is_ok());
    assert!(window.validate_nonce(RawNonce::new(0), &must_not_be_called).is_err());
    assert!(window.validate_nonce(RawNonce::new(1), &must_not_be_called).is_err());
    assert!(window.require_empty_relative(0, 0).is_err());
    assert!(window.require_empty_relative(0, 63).is_err());
    assert!(window.require_empty_relative(1, 0).is_err());

    // Check: we can deliver missing out-of-order.
    assert!(window.require_empty_relative(0, 1).is_ok());
    assert!(window.validate_nonce(RawNonce::new(63), &err).is_err());
    assert!(window.require_empty_relative(0, 1).is_ok());
    assert!(window.validate_nonce(RawNonce::new(63), &ok).is_ok());
    assert!(window.require_empty_relative(0, 1).is_err());
    assert!(window.validate_nonce(RawNonce::new(63), &must_not_be_called).is_err());
}
