// Use `StaticSecret` since the responder does two DH-applications.
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use super::{CounterNonce, NotSoSafeKey, Nonce, RawNonce, SlidingWindowNonce, UnspecifiedCryptoFailure};

trait Rng: rand_core::RngCore + rand_core::CryptoRng {}
impl<T: rand_core::RngCore + rand_core::CryptoRng> Rng for T {}

/// The environment available for operations.
///
/// This contains the rng for example.
pub struct System {
    rng: alloc::boxed::Box<dyn Rng>,
}

impl System {
    pub const CONSTRUCTION: &'static str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
    pub const IDENTIFIER: &'static str = "WireGuard v1 zx2c4 Jason@zx2c4.com";
    pub const LABEL_MAC1: &'static str = "mac1----";
    pub const LABEL_COOKIE: &'static str = "cookie--";

    pub fn new() -> Self {
        use rand_core::SeedableRng;
        let mut os = rand::rngs::OsRng;
        let chacha = rand_chacha::ChaChaRng::from_rng(&mut os)
            .expect("No initial randomness for internal RNG");
        System {
            rng: alloc::boxed::Box::new(chacha),
        }
    }

    pub fn dh(&mut self, private: &StaticSecret, public: &PublicKey) -> SharedSecret {
        private.diffie_hellman(public)
    }

    pub fn dh_generate(&mut self) -> StaticSecret {
        StaticSecret::new(&mut self.rng)
    }

    /// Seal one message using a counter to generate the nonce.
    pub fn aead(
        &mut self,
        key: &NotSoSafeKey,
        nonce: &mut CounterNonce,
        plain_plus_tag: &mut [u8],
        ad: &[u8],
    ) -> Result<(), UnspecifiedCryptoFailure> {
        let nonce = nonce.next_nonce()?;
        todo!()
    }

    /// Unseal one message using a sliding window acceptance window.
    pub fn undo_aead(
        &mut self,
        key: &NotSoSafeKey,
        nonce_check: &mut SlidingWindowNonce,
        nonce: RawNonce,
        plain_plus_tag: &mut [u8],
        ad: &[u8],
    ) -> Result<(), UnspecifiedCryptoFailure> {
        nonce_check.validate_nonce(nonce, |nonce| {
            todo!()
        })
    }

    /// Seal one message with a new random nonce.
    pub fn xaead(
        &mut self,
        key: &NotSoSafeKey,
        plain_plus_tag: &mut [u8],
        ad: &[u8],
    ) -> RawNonce {
        todo!()
    }

    pub fn hash(&mut self, value: &[u8]) -> [u8; 32] {
        todo!()
    }

    pub fn mac(&mut self, key: &NotSoSafeKey, value: &[u8]) -> [u8; 16] {
        todo!()
    }

    pub fn hmac(&mut self, key: &NotSoSafeKey, value: &[u8]) -> [u8; 32] {
        todo!()
    }

    pub fn kdf(&mut self, key: &NotSoSafeKey, value: &[u8])
        -> impl Iterator<Item=[u8; 32]> + '_
    {
        struct IterMac<'system> {
            system: &'system mut System,
            tau0: NotSoSafeKey,
            taui: [u8; 32],
            i: u8,
        }

        impl Iterator for IterMac<'_> {
            type Item = [u8; 32];
            fn next(&mut self) -> Option<Self::Item> {
                let next_i = self.i.checked_add(1)?;

                let mut bytes: [u8; 33] = [0; 33];
                bytes.copy_from_slice(&self.taui);
                bytes[32] = next_i;
                let next_tau = self.system.hmac(&self.tau0, &bytes[..]);

                let tau_out = self.taui;
                self.taui = next_tau;
                self.i = next_i;
                Some(tau_out)
            }
        }

        let tau0 = NotSoSafeKey::from(self.hmac(key, value));
        let taui = self.hmac(&tau0, &[0x1u8]);

        IterMac {
            system: self,
            tau0,
            taui,
            i: 1,
        }
    }

    pub fn timestamp(&mut self) -> [u8; 12] {
        todo!()
    }
}
