// Use `StaticSecret` since the responder does two DH-applications.
use blake2::{Blake2s, VarBlake2s};
use blake2::digest::Update;
use hmac::{Hmac, Mac, NewMac};
use super::{ChaCha20Poly1305Nonce, CounterNonce, NotSoSafeKey, RawNonce, SlidingWindowNonce, UnspecifiedCryptoFailure};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305, Tag};
use chacha20poly1305::aead::{AeadInPlace, NewAead};

trait Rng: rand_core::RngCore + rand_core::CryptoRng {}
impl<T: rand_core::RngCore + rand_core::CryptoRng> Rng for T {}

/// The environment available for operations.
///
/// This contains the rng for example.
pub(crate) struct System {
    rng: alloc::boxed::Box<dyn Rng>,
}

impl System {
    pub(crate) const CONSTRUCTION: &'static str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
    pub(crate) const IDENTIFIER: &'static str = "WireGuard v1 zx2c4 Jason@zx2c4.com";
    pub(crate) const LABEL_MAC1: &'static str = "mac1----";
    pub(crate) const LABEL_COOKIE: &'static str = "cookie--";

    pub(crate) fn new() -> Self {
        use rand_core::SeedableRng;
        let mut os = rand::rngs::OsRng;
        let chacha = rand_chacha::ChaChaRng::from_rng(&mut os)
            .expect("No initial randomness for internal RNG");
        System {
            rng: alloc::boxed::Box::new(chacha),
        }
    }

    pub(crate) fn dh(&mut self, private: &StaticSecret, public: &PublicKey) -> SharedSecret {
        private.diffie_hellman(public)
    }

    pub(crate) fn dh_generate(&mut self) -> (StaticSecret, PublicKey) {
        let private = StaticSecret::new(&mut self.rng);
        let public = PublicKey::from(&private);
        (private, public)
    }

    /// Seal one message using a counter to generate the nonce.
    pub fn aead(
        &mut self,
        key: &NotSoSafeKey,
        nonce: &mut CounterNonce,
        plain_plus_tag: &mut [u8],
        ad: &[u8],
    ) -> Result<(), UnspecifiedCryptoFailure> {
        let (text, tag) = Self::split_plain_text_plus_tag(plain_plus_tag)?;
        let nonce = nonce.next_nonce()?;
        let aead = XChaCha20Poly1305::new(key);
        *tag = aead.encrypt_in_place_detached(nonce.as_xaead_nonce(), ad, text)
            .map_err(|_| UnspecifiedCryptoFailure)?;
        Ok(())
    }

    /// Unseal one message using a sliding window acceptance window.
    pub(crate) fn undo_aead(
        &mut self,
        key: &NotSoSafeKey,
        nonce_check: &mut SlidingWindowNonce,
        nonce: RawNonce,
        plain_plus_tag: &mut [u8],
        ad: &[u8],
    ) -> Result<(), UnspecifiedCryptoFailure> {
        let (text, tag) = Self::split_plain_text_plus_tag(plain_plus_tag)?;
        nonce_check.validate_nonce(nonce, |nonce| {
            let aead = XChaCha20Poly1305::new(key);
            aead.decrypt_in_place_detached(nonce.as_xaead_nonce(), ad, text, tag)
                .map_err(|_| UnspecifiedCryptoFailure)
        })
    }

    fn split_plain_text_plus_tag(buf: &mut [u8])
        -> Result<(&mut [u8], &mut Tag), UnspecifiedCryptoFailure>
    {
        let tag_len = Tag::default().len();

        if let Some(text_len) = buf.len().checked_sub(tag_len) {
            let (text, tag) = buf.split_at_mut(text_len);
            let tag = Tag::from_mut_slice(tag);
            Ok((text, tag))
        } else {
            Err(UnspecifiedCryptoFailure)
        }
    }

    /// Seal one message with a new random nonce.
    pub(crate) fn xaead(
        &mut self,
        key: &NotSoSafeKey,
        plain_plus_tag: &mut [u8],
        ad: &[u8],
    ) -> Result<ChaCha20Poly1305Nonce, UnspecifiedCryptoFailure> {
        let (text, tag) = Self::split_plain_text_plus_tag(plain_plus_tag)?;
        let nonce = {
            let mut uninit = *RawNonce::new(0).as_aead_nonce();
            self.rng.fill_bytes(uninit.as_mut_slice());
            uninit
        };
        let aead = ChaCha20Poly1305::new(key);
        *tag = aead.encrypt_in_place_detached(&nonce, ad, text)
            .map_err(|_| UnspecifiedCryptoFailure)?;
        Ok(nonce)
    }

    /// Minimal deviation, we accept a sequence to hash over.
    pub(crate) fn hash<'any>(&mut self, values: impl IntoIterator<Item=&'any [u8]>) -> [u8; 32] {
        use digest::VariableOutputDirty;
        let mut hasher = VarBlake2s::new_keyed(&[], 32);
        for value in values {
            hasher.update(value);
        }
        let mut output = [0u8; 32];
        hasher.finalize_variable_dirty(|cb| output.copy_from_slice(cb));
        output
    }

    /// And the standard interface for a single slice.
    pub(crate) fn hash_one(&mut self, value: &[u8]) -> [u8; 32] {
        self.hash(core::iter::once(value))
    }

    pub(crate) fn mac(&mut self, key: &NotSoSafeKey, value: &[u8]) -> [u8; 16] {
        use digest::VariableOutputDirty;
        let mut keyed = VarBlake2s::new_keyed(key.as_slice(), 16);
        keyed.update(value);
        let mut output = [0u8; 16];
        keyed.finalize_variable_dirty(|cb| output.copy_from_slice(cb));
        output
    }

    pub(crate) fn hmac(&mut self, key: &NotSoSafeKey, value: &[u8]) -> [u8; 32] {
        let mut hmac = Hmac::<Blake2s>::new_varkey(key.as_slice()).unwrap();
        hmac.update(value);
        let generic = hmac.finalize().into_bytes();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&generic.as_slice());
        bytes
    }

    pub(crate) fn kdf(&mut self, key: &NotSoSafeKey, value: &[u8])
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
                bytes[..32].copy_from_slice(&self.taui[..32]);
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

    pub(crate) fn timestamp(&mut self) -> [u8; 12] {
        todo!()
    }
}

#[test]
fn test_handshake() {
    let mut system = System::new();
    let (priv_i, pub_i) = system.dh_generate();
    let (priv_r, pub_r) = system.dh_generate();

    let (epub_i, epub_r);
    let (saved_epriv_i, saved_epriv_r);

    // Things that are transported over the channel.
    let (
        msg_eph,
        mut msg_static,
        msg_static_hash,
        msg_static_key,
        mut msg_timestamp,
        msg_timestamp_hash,
        msg_timestamp_key,
        msg_c,
        msg_h,
    );

    {
        // The initiator side.
        let c_i = system.hash_one(System::CONSTRUCTION.as_bytes());
        let h_i = system.hash([&c_i, System::IDENTIFIER.as_bytes()].iter().cloned());
        let h_i = system.hash([&h_i[..], pub_r.as_bytes()].iter().cloned());

        let (epriv_i, pre_epub_i) = system.dh_generate();
        epub_i = pre_epub_i;
        msg_eph = epub_i;
        let c_i = NotSoSafeKey::from(c_i);
        let c_i = system.kdf(&c_i, epub_i.as_bytes()).next().unwrap();

        let h_i = system.hash([&h_i[..], msg_eph.as_bytes()].iter().cloned());
        let (c_i, k) = {
            let c_i = NotSoSafeKey::from(c_i);
            let dh = system.dh(&epriv_i, &pub_r);
            let mut kdf = system.kdf(&c_i, dh.as_bytes());
            (kdf.next().unwrap(), kdf.next().unwrap())
        };
        let mut counter = CounterNonce::default();
        msg_static = [0; 32+16];
        msg_static[..32].copy_from_slice(pub_i.as_bytes());
        system.aead(
            &NotSoSafeKey::from(k),
            &mut counter,
            &mut msg_static[..],
            &h_i
        ).unwrap();
        msg_static_key = k;
        msg_static_hash = h_i;

        let (c_i, k) = {
            let c_i = NotSoSafeKey::from(c_i);
            let dh = system.dh(&priv_i, &pub_r);
            let mut kdf = system.kdf(&c_i, dh.as_bytes());
            (kdf.next().unwrap(), kdf.next().unwrap())
        };

        let mut counter = CounterNonce::default();
        // We don't check or send the timestamp, just the binding hash..
        msg_timestamp = [0; 12+16];
        system.aead(
            &NotSoSafeKey::from(k),
            &mut counter,
            &mut msg_timestamp[..],
            &h_i
        ).unwrap();
        msg_timestamp_key = k;
        msg_timestamp_hash = h_i;

        let h_i = system.hash([&h_i[..], &msg_timestamp[..]].iter().cloned());
        msg_c = c_i;
        msg_h = h_i;

        saved_epriv_i = epriv_i;
    }

    let (
        rsp_eph,
        mut rsp_empty,
        rsp_empty_key,
        rsp_empty_hash,
        // these are implicit transmissions..
        rsp_c,
        rsp_h,
        // Pre-Shared key Q.
        rsp_q,
    );

    {
        let mut nonce = SlidingWindowNonce::default();
        system.undo_aead(
            &NotSoSafeKey::from(msg_static_key),
            &mut nonce,
            RawNonce::new(0),
            &mut msg_static,
            &msg_static_hash,
        ).expect("Unsealing static message failed");
        assert_eq!(&msg_static[..32], pub_i.as_bytes());

        let mut nonce = SlidingWindowNonce::default();
        system.undo_aead(
            &NotSoSafeKey::from(msg_timestamp_key),
            &mut nonce,
            RawNonce::new(0),
            &mut msg_timestamp,
            &msg_timestamp_hash,
        ).expect("Unsealing time stamp failed");
        assert_eq!(&msg_timestamp[..12], &[0; 12][..]);

        let (epriv_r, pre_epub_r) = system.dh_generate();
        epub_r = pre_epub_r;

        let c_r = msg_c;
        let h_r = msg_h;

        let c_r = NotSoSafeKey::from(c_r);
        let c_r = system.kdf(&c_r, epub_r.as_bytes()).next().unwrap();
        rsp_eph = epub_r;

        let h_r = system.hash([&h_r[..], rsp_eph.as_bytes()].iter().cloned());
        let c_r = {
            let dh = system.dh(&priv_r, &epub_i);
            let c_r = NotSoSafeKey::from(c_r);
            system.kdf(&c_r, dh.as_bytes()).next().unwrap()
        };
        let c_r = {
            let dh = system.dh(&epriv_r, &pub_i);
            let c_r = NotSoSafeKey::from(c_r);
            system.kdf(&c_r, dh.as_bytes()).next().unwrap()
        };

        let (c_r, t, k) = {
            // Assuming definition of Q here..
            let q = system.dh(&epriv_r, &epub_i);
            let c_r = NotSoSafeKey::from(c_r);
            let mut kdf = system.kdf(&c_r, q.as_bytes());
            rsp_q = q;

            (kdf.next().unwrap(), kdf.next().unwrap(), kdf.next().unwrap())
        };

        let h_r = system.hash([&h_r[..], &t[..]].iter().cloned());

        let mut counter = CounterNonce::default();
        rsp_empty = [0u8; 0+16];
        system.aead(
            &NotSoSafeKey::from(k),
            &mut counter,
            &mut rsp_empty,
            &h_r,
        ).unwrap();
        rsp_empty_key = k;
        rsp_empty_hash = h_r;

        let h_r = system.hash([&h_r[..], &rsp_empty[..]].iter().cloned());
        rsp_c = c_r;
        rsp_h = h_r;

        saved_epriv_r = epriv_r;
    }

    // Final check by initiator..
    {
        let msg_q = system.dh(&saved_epriv_i, &epub_r);
        assert_eq!(msg_q.as_bytes(), rsp_q.as_bytes());

        let mut nonce = SlidingWindowNonce::default();
        system.undo_aead(
            &NotSoSafeKey::from(rsp_empty_key),
            &mut nonce,
            RawNonce::new(0),
            &mut rsp_empty,
            &rsp_empty_hash,
        ).expect("Unsealing static message failed");
    }

    // Those would be used only when proceeding..
    let _ = (rsp_c, rsp_h, saved_epriv_r);
}
