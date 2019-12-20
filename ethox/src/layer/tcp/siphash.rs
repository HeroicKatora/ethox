//! Initial sequence number generation, as recommended by rfc6528.
//!
//! Uses a keyed cryptographic hash function (SipHash-2-4) instead of appending the secret key to
//! the four tuple for hashing. That should be better anyways. Hash function SipHash-2-4 from:
//!
//! > SipHash: a fast short-input PRFJean-Philippe Aumasson1and Daniel J. Bernstein
use super::endpoint::FourTuple;
use crate::time::Instant;
use crate::wire::{IpAddress, Ipv6Address, TcpSeqNumber};

/// An initial sequence number generator based on SipHash-2-4.
///
/// Implements most RFC6528 but with a particular choice of keyed hash function (instead of MD5).
/// Also, instead of hashing the secret as the last parameter the hash function already provides a
/// setup for keyed use that can be precomputed.
///
/// > ISN = M + SipHash-2-4(secretkey, localip, localport, remoteip, remoteport)
///
/// The security of 2-4 might be better than what is required for some usecases and in some cases a
/// SipHash-1-3 might instead be adequate. If this is indeed the case for Your use then You are
/// invited to provide a PR introducing such a switch of hash function internally.
///
/// Parameters that are unlikely to be accepted: 
/// * SipHash-4-8, the conservative proposed variant for cryptographic MAC, is twice as expensive
///   to compute and unlikely to have a practical advantage. Note that any attacker is highly limited
///   in modifications to the hash input and a collision (second pre-image) is not her goal.
/// * SipHash-0-x, there exist key recovery attacks and it only has marginal extra 
pub struct IsnGenerator {
    keys: (u64, u64),
}

// Yes, that's the initial values, as ASCII text.
const IV: [&[u8; 8]; 4] = [
    b"somepseu",
    b"dorandom",
    b"lygenera",
    b"tedbytes"];

struct State {
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
}

impl IsnGenerator {
    /// Create a generator by deriving a key from the standard `RandomState`.
    ///
    /// This is done by individually hashing the numbers `0u64` and `1u64` each with the same
    /// hasher created from a new instance of `RandomState`. The two output tags are then used as
    /// the internal key state.
    #[cfg(feature = "std")]
    pub fn from_std_hash() -> Self {
        use std::hash::{Hasher, BuildHasher};
        use std::collections::hash_map::RandomState;

        let hash = RandomState::new().build_hasher();
        let x0 = {
            let mut hash = hash.clone();
            hash.write_u64(0);
            hash.finish()
        };
        let x1 = {
            let mut hash = hash.clone();
            hash.write_u64(1);
            hash.finish()
        };

        IsnGenerator {
            keys: (x0, x1),
        }
    }

    /// Create a generator with some pre-defined secret key.
    ///
    /// Really, create the key with some cryptographic random means or derive them from some other
    /// key with a key derivation function.
    pub fn from_secret_key_bytes(bytes: [u8; 16]) -> Self {
        use core::convert::TryInto;
        let a = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        let b = u64::from_le_bytes(bytes[8..].try_into().unwrap());
        IsnGenerator { keys: (a, b), }
    }

    /// Create a generator with a pre-defined key.
    #[cfg(test)]
    pub fn from_key(a: u64, b: u64) -> Self {
        IsnGenerator { keys: (a, b), }
    }

    /// Get the initial sequence number for a connection.
    ///
    /// The value varies every 4ms or when the underlying secret key is updated.
    ///
    /// # Panics
    ///
    /// This function panics if the connection tuple contains anything other than an IPv4 and IPv6
    /// connection pair (i.e. the Invalid state). This may be statically checked in the future
    /// through some other connection representation.
    pub fn get_isn(&self, connection: FourTuple, time: Instant) -> TcpSeqNumber {
        let mut state = State::init(self.keys.0, self.keys.1);

        let num = match (connection.local, connection.remote) {
            (IpAddress::Ipv4(here), IpAddress::Ipv4(there)) => {
                let m = u64::from(here.to_network_integer())
                    | u64::from(there.to_network_integer()) << 32;
                let p = u64::from(connection.local_port)
                    | u64::from(connection.remote_port) << 16
                    // Message length = 12
                    | 12_u64 << 56;
                state.absorb(m);
                state.absorb(p);
                state.finalize()
            },
            (IpAddress::Ipv6(here), IpAddress::Ipv6(there)) => {
                let (m0, m1) = Self::ipv6_to_messages(here);
                let (m2, m3) = Self::ipv6_to_messages(there);
                let p = u64::from(connection.local_port)
                    | u64::from(connection.remote_port) << 16
                    // Message length = 20
                    | 20_u64 << 56;
                state.absorb(m0);
                state.absorb(m1);
                state.absorb(m2);
                state.absorb(m3);
                state.absorb(p);
                state.finalize()
            },
            // Don't even know how we could get here, but maybe with mapped addresses.
            (IpAddress::Ipv4(here), IpAddress::Ipv6(there)) => {
                let m0 = u64::from(here.to_network_integer())
                    | u64::from(connection.local_port) << 32
                    | u64::from(connection.remote_port) << 48;
                let (m1, m2) = Self::ipv6_to_messages(there);
                // Message length = 16
                let p = 16_u64 << 56;
                state.absorb(m0);
                state.absorb(m1);
                state.absorb(m2);
                state.absorb(p);
                state.finalize()
            },
            (IpAddress::Ipv6(here), IpAddress::Ipv4(there)) => {
                let (m0, m1) = Self::ipv6_to_messages(here);
                let m2 = u64::from(there.to_network_integer())
                    | u64::from(connection.local_port) << 32
                    | u64::from(connection.remote_port) << 48;
                // Message length = 16
                let p = 16_u64 << 56;
                state.absorb(m0);
                state.absorb(m1);
                state.absorb(m2);
                state.absorb(p);
                state.finalize()
            },
            // FIXME: this really shouldn't be hit. We should introdce a good enum for Ip addresses
            // to guarantee this statically.
            _ => panic!("Should not be called, four tuple needs to be concrete ip addresses"),
        };

        TcpSeqNumber(num as i32) + (time.millis()/4000) as usize
    }

    fn ipv6_to_messages(addr: Ipv6Address) -> (u64, u64) {
        let Ipv6Address([a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p]) = addr;
        let m0 = u64::from_be_bytes([a, b, c, d, e, f, g, h]);
        let m1 = u64::from_be_bytes([i, j, k, l, m, n, o, p]);
        (m0, m1)
    }
}

impl State {
    const SIP_C: usize = 2;
    const SIP_D: usize = 4;

    fn init(k0: u64, k1: u64) -> Self {
        State {
            v0: u64::from_be_bytes(*IV[0]) ^ k0,
            v1: u64::from_be_bytes(*IV[1]) ^ k1,
            v2: u64::from_be_bytes(*IV[2]) ^ k0,
            v3: u64::from_be_bytes(*IV[3]) ^ k1,
        }
    }

    fn round(&mut self) {
        self.v0 = self.v0.wrapping_add(self.v1);
        self.v1 = self.v1.rotate_left(13);
        self.v1 ^= self.v0;
        self.v0 = self.v0.rotate_left(32);
        self.v2 = self.v2.wrapping_add(self.v3);
        self.v3 = self.v3.rotate_left(16);
        self.v3 ^= self.v2;
        self.v0 = self.v0.wrapping_add(self.v3);
        self.v3 = self.v3.rotate_left(21);
        self.v3 ^= self.v0;
        self.v2 = self.v2.wrapping_add(self.v1);
        self.v1 = self.v1.rotate_left(17);
        self.v1 ^= self.v2;
        self.v2 = self.v2.rotate_left(32);
    }

    /// Process a single portion of the message.
    ///
    /// Note that all users need to manually add absorbing the length in the last block. This is
    /// slightly easier to read since it arranges the input to only have 8-btye blocks in all cases
    /// which separates the length block completely and makes it a constant.
    fn absorb(&mut self, m: u64) {
        self.v3 ^= m;
        (0..Self::SIP_C).for_each(|_| self.round());
        self.v0 ^= m;
    }

    /// Do the finalization rounds.
    fn finalize(mut self) -> u64 {
        self.v2 ^= 0xff;
        (0..Self::SIP_D).for_each(|_| self.round());
        self.v0 ^ self.v1 ^ self.v2 ^ self.v3
    }
}

#[cfg(test)]
mod tests {
    use core::fmt;
    use super::*;

    struct DebugState<'a>(&'a State);

    impl fmt::Debug for DebugState<'_> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{:x} ", self.0.v0)?;
            write!(f, "{:x} ", self.0.v1)?;
            write!(f, "{:x} ", self.0.v2)?;
            write!(f, "{:x} ", self.0.v3)
        }
    }

    impl super::State {
        fn debug(&self) -> DebugState {
            DebugState(self)
        }
    }

    /// See the paper–Appendix A
    #[test]
    fn manual_test_vectors() {
        let k0 = u64::from_le_bytes(0x0001020304050607_u64.to_be_bytes());
        let k1 = u64::from_le_bytes(0x08090a0b0c0d0e0f_u64.to_be_bytes());

        let mut state = State::init(k0, k1);
        println!("{:?}", state.debug());
        let m0 = u64::from_le_bytes(0x0001020304050607_u64.to_be_bytes());
        state.absorb(m0);
        println!("{:?}", state.debug());
        let m1 = u64::from_le_bytes(0x08090a0b0c0d0e0f_u64.to_be_bytes());
        state.absorb(m1);
        println!("{:?}", state.debug());

        assert_eq!(state.finalize(), 0xa129ca6149be45e5);
    }
}
