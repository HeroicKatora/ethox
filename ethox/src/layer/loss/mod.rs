//! Simulates packet loss.
//!
//! The loss layer is a simple wrapper around another layer which simulates a lossy connection.
//! This works by dropping ingress packets or canceling the sending of egress packets.

/// Simple pseudo-random loss.
///
/// Can simulate burst-losses and uniform losses by dropping packets based on a pulse design.
#[derive(Clone, Debug, Hash)]
pub struct PrngLoss {
    /// Threshold for dropping the packet.
    pub threshold: u32,
    /// The packet is never dropped while `count` at least as large as `threshold`.
    pub count: u32,
    /// Reset value for `count` when it reaches `0`.
    pub reset: u32,
    /// Loss rate as a (0, 32)-bit fixed point number.
    ///
    /// Or `None` for no loss at all, which can be used to temporarily turn loss off.
    pub lossrate: Option<u32>,
    /// The current prng state (or seed at the start).
    ///
    /// Xoroshiro256**, yes this is far too good.
    pub prng: Xoroshiro256,
}

#[derive(Clone, Debug, Hash)]
pub struct Xoroshiro256 {
    state: [u64; 4],
}

impl PrngLoss {
    /// A uniform loss simulator.
    pub fn uniform(rate: Option<u32>, seed: u64) -> Self {
        PrngLoss {
            // Threshold always greater than count
            threshold: 1,
            count: 0,
            reset: 0,
            lossrate: rate,
            prng: Xoroshiro256::new(seed),
        }
    }

    /// Simulate burst losses as pulses.
    ///
    /// Drops all packets while in a high state, lets packets pass while in low state.
    pub fn pulsed(high: u32, length: u32) -> Self {
        assert!(length > 0, "Pulse length must not be zero");
        assert!(high <= length, "Length of high signals must be shorter than total length");
        PrngLoss {
            threshold: high,
            count: length - 1,
            reset: length - 1,
            // Packet always lost when pulse condition is true.
            lossrate: Some(u32::max_value()),
            prng: Xoroshiro256::new(0),
        }
    }

    /// Determine the fate for the next packet.
    pub fn next(&mut self) -> bool {
        let in_window = self.count < self.threshold;
        let fate = Some(self.roll()) <= self.lossrate;

        let ncount = self.count.checked_sub(1)
            .unwrap_or(self.reset);
        self.count = ncount;

        fate & in_window
    }

    /// Generate the next value of the prng.
    fn roll(&mut self) -> u32 {
        (self.prng.next() & u64::from(!0u32)) as u32
    }
}

impl Xoroshiro256 {
    pub fn new(seed: u64) -> Self {
        Xoroshiro256 {
            state: [seed, 0, 0, 0],
        }
    }

    pub fn next(&mut self) -> u64 {
        let s = &mut self.state;
		let result_starstar = s[1]
            .wrapping_mul(5)
            .rotate_left(7)
            .wrapping_mul(9);

		let t = s[1] << 17;

		s[2] ^= s[0];
		s[3] ^= s[1];
		s[1] ^= s[2];
		s[0] ^= s[3];

		s[2] ^= t;

		s[3] = s[3].rotate_left(45);

		result_starstar
    }
}

#[cfg(test)]
mod tests {
    use super::PrngLoss;

    #[test]
    fn pulsed() {
        // Drops one out of 10 packets.
        let mut prng = PrngLoss::pulsed(1, 10);
        let count = (0..100)
            .filter(|_| prng.next())
            .count();
        assert_eq!(count, 10);

        // Drops all packets.
        prng = PrngLoss::pulsed(1, 1);
        let count = (0..100)
            .filter(|_| prng.next())
            .count();
        assert_eq!(count, 100);

        // Drops at most one out of 10 packets.
        prng = PrngLoss::pulsed(1, 10);
        prng.lossrate = Some(!0 >> 1);
        let count = (0..100)
            .filter(|_| prng.next())
            .count();
        assert!(count <= 10);
    }
}

