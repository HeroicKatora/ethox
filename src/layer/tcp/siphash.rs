//! Initial sequence number generation, as recommended by rfc6528.
//!
//! Uses a keyed cryptographic hash function (SipHash-2-4) instead of appending the secret key to
//! the four tuple for hashing. That should be better anyways. Hash function SipHash-2-4 from:
//!
//! > SipHash: a fast short-input PRFJean-Philippe Aumasson1and Daniel J. Bernstein
use super::endpoint::FourTuple;
use crate::time::Instant;
use crate::wire::{IpAddress, Ipv6Address, TcpSeqNumber};

pub struct IsnGenerator {
    keys: (u64, u64),
}

// Yes, that's the initial values.
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
    /// Get the initial sequence number for a connection.
    ///
    /// The value varies every 4ms or when the underlying secret key is updated.
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
    fn absorb(&mut self, m: u64) {
        self.v3 ^= m;
        (0..Self::SIP_C).for_each(|_| self.round());
        self.v0 ^= m;
    }

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
