// Use `StaticSecret` since the responder does two DH-applications.
use core::convert::TryFrom;
use blake2::{Blake2s, VarBlake2s};
use blake2::digest::Update;
use hmac::{Hmac, Mac, NewMac};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305, Tag};
use chacha20poly1305::aead::{AeadInPlace, NewAead};

use super::{ChaCha20Poly1305Nonce, CounterNonce, NotSoSafeKey, RawNonce, SlidingWindowNonce, UnspecifiedCryptoFailure};
use super::wire::wireguard;

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
        -> impl Iterator<Item=NotSoSafeKey> + '_
    {
        struct IterMac<'system> {
            system: &'system mut System,
            tau0: NotSoSafeKey,
            taui: [u8; 32],
            i: u8,
        }

        impl Iterator for IterMac<'_> {
            type Item = NotSoSafeKey;
            fn next(&mut self) -> Option<Self::Item> {
                let next_i = self.i.checked_add(1)?;
                let mut bytes: [u8; 33] = [0; 33];
                bytes[..32].copy_from_slice(&self.taui[..32]);
                bytes[32] = next_i;
                let next_tau = self.system.hmac(&self.tau0, &bytes[..]);
                // Publish new key, we haven't leaked it yet.
                let tau_out = NotSoSafeKey::from(self.taui);
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

    fn kdf1(&mut self, c_i: NotSoSafeKey, context: &[u8]) -> NotSoSafeKey {
        NotSoSafeKey::from(self.kdf(&c_i, context).next().unwrap())
    }

    fn kdf2(&mut self, c_i: NotSoSafeKey, context: &[u8]) -> (NotSoSafeKey, NotSoSafeKey) {
        let mut kdf = self.kdf(&c_i, context);
        let k0 = NotSoSafeKey::from(kdf.next().unwrap());
        let k1 = NotSoSafeKey::from(kdf.next().unwrap());
        (k0, k1)
    }

    fn kdf3(&mut self, c_i: NotSoSafeKey, context: &[u8]) -> (NotSoSafeKey, NotSoSafeKey, NotSoSafeKey) {
        let mut kdf = self.kdf(&c_i, context);
        let k0 = NotSoSafeKey::from(kdf.next().unwrap());
        let k1 = NotSoSafeKey::from(kdf.next().unwrap());
        let k2 = NotSoSafeKey::from(kdf.next().unwrap());
        (k0, k1, k2)
    }

    fn update_hash(&mut self, rolling: [u8; 32], context: &[u8]) -> [u8; 32] {
        self.hash([&rolling[..], context].iter().cloned())
    }
}

impl super::This {
    /// Prepare a handshake with one particular peer.
    ///
    /// This does some pre-calculation.
    pub fn prepare(&mut self, to: &super::Peer) -> super::PreHandshake {
        super::PreHandshake::for_peer(&mut self.system, to)
    }
}

impl super::PreHandshake {
    pub(crate) fn for_peer(system: &mut System, to: &super::Peer) -> Self {
        let c_i = system.hash_one(System::CONSTRUCTION.as_bytes());
        let h_i = system.hash([&c_i, System::IDENTIFIER.as_bytes()].iter().cloned());
        let h_i = system.hash([&h_i[..], to.public.as_bytes()].iter().cloned());
        let c = system.hash([&System::LABEL_MAC1.as_bytes()[..], to.public.as_bytes()].iter().cloned());

        super::PreHandshake {
            initiator_key: NotSoSafeKey::from(c_i),
            initiator_hash: h_i,
            mac1_key: NotSoSafeKey::from(c),
            peer_public: to.public,
        }
    }
}

impl super::PostInitHandshake {
    /// Handshake with the message, sealing it in the process.
    /// # Panics
    /// The `msg` MUST already be validated to be an init message.
    pub(crate) fn write(this: &mut super::This, pre: &super::PreHandshake, msg: &mut wireguard)
        -> Result<Self, UnspecifiedCryptoFailure>
    {
        let c_i = pre.initiator_key;
        let h_i = pre.initiator_hash;
        let system = &mut this.system;

        // (Eprivi,Epubi):=DH-Generate()
        let (epriv_i, epub_i) = system.dh_generate();
        // Ci:=Kdf1(Ci,Epubi)
        let c_i = system.kdf1(c_i, epub_i.as_bytes());
        // msg.ephemeral:=Epubi
        msg.init_ephemeral().copy_from_slice(epub_i.as_bytes());
        // Hi:=Hash(Hi‖msg.ephemeral)
        let h_i = system.update_hash(h_i, msg.init_ephemeral());
        // (Ci,κ):=Kdf2(Ci,DH(Eprivi,Spubr))
        let (c_i, k) = {
            let dh = system.dh(&epriv_i, &this.public);
            system.kdf2(c_i, dh.as_bytes())
        };
        // msg.static:=Aead(κ,0,Spubi,Hi)
        let msg_static = msg.init_static();
        msg_static[..32].copy_from_slice(this.public.as_bytes());
        system.aead(
            &k,
            &mut CounterNonce::default(),
            &mut msg_static[..],
            &h_i
        ).unwrap();
        // Hi:=Hash(Hi‖msg.static)
        let h_i = system.update_hash(h_i, msg.init_static());
        // (Ci,κ):=Kdf2(Ci,DH(Sprivi,Spubr))
        let (c_i, k) = {
            let dh = system.dh(&this.private, &pre.peer_public);
            system.kdf2(c_i, dh.as_bytes())
        };
        // msg.timestamp:=Aead(κ,0,Timestamp(),Hi)
        let msg_timestamp = msg.init_timestamp();
        system.aead(
            &k,
            &mut CounterNonce::default(),
            &mut msg_timestamp[..],
            &h_i
        ).unwrap();
        // Hi:=Hash(Hi‖msg.timestamp)
        let h_i = system.update_hash(h_i, msg_timestamp);

        Ok(super::PostInitHandshake {
            initiator_key: NotSoSafeKey::from(c_i),
            initiator_hash: h_i,
            initiator_public: this.public,
            ephemeral_public: epub_i,
            ephemeral_private: Some(epriv_i),
        })
    }

    /// Handshake with the message, unsealing it in the process.
    /// # Panics
    /// The `msg` MUST already be validated to be an init message.
    pub(crate) fn for_incoming(this: &mut super::This, pre: &super::PreHandshake, msg: &mut wireguard)
        -> Result<Self, UnspecifiedCryptoFailure>
    {
        let c_i = pre.initiator_key;
        let h_i = pre.initiator_hash;
        let system = &mut this.system;

        // Epubi:=msg.ephemeral
        let epub_i = msg.init_ephemeral();
        let epub_i: &[u8; 32] = TryFrom::try_from(&epub_i[..]).unwrap();
        let epub_i = PublicKey::from(*epub_i);
        // Ci:=Kdf1(Ci,Epubi)
        let c_i = system.kdf1(c_i, epub_i.as_bytes());
        // Hi:=Hash(Hi‖msg.ephemeral)
        let h_i = system.update_hash(h_i, epub_i.as_bytes());
        // (Ci,κ):=Kdf2(Ci,DH(Epubi,Sprivr))
        let (c_i, k) = {
            let dh = system.dh(&this.private, &epub_i);
            system.kdf2(c_i, dh.as_bytes())
        };
        // Aead(κ,0,Spubi,Hi)?=msg.static
        let msg_static = msg.init_static();
        system.undo_aead(
            &k,
            &mut SlidingWindowNonce::default(),
            RawNonce::new(0),
            &mut msg_static[..],
            &h_i,
        )?;
        // Hi:=Hash(Hi‖msg.static)
        let h_i = system.update_hash(h_i, msg_static);
        // (Ci,κ):=Kdf2(Ci,DH(Spubi,Sprivr))
        let (c_i, k) = {
            let dh = system.dh(&this.private, &epub_i);
            system.kdf2(c_i, dh.as_bytes())
        };
        // Aead(κ,0,Timestamp(),Hi)?=msg.timestamp
        let msg_timestamp = msg.init_timestamp();
        system.undo_aead(
            &k,
            &mut SlidingWindowNonce::default(),
            RawNonce::new(0),
            &mut msg_timestamp[..],
            &h_i,
        )?;
        // Hi:=Hash(Hi‖msg.timestamp)
        let h_i = system.update_hash(h_i, msg_timestamp);

        Ok(super::PostInitHandshake {
            initiator_key: c_i,
            initiator_hash: h_i,
            initiator_public: pre.peer_public,
            ephemeral_public: epub_i,
            ephemeral_private: None,
        })
    }
}

extern "Rust" {
    fn invoke_q() -> NotSoSafeKey;
}

impl super::PostResponseHandshake {
    /// Handshake with the message, sealing it in the process.
    /// # Panics
    /// The `msg` MUST already be validated to be an init message.
    pub(crate) fn write(this: &mut super::This, pre: super::PostInitHandshake, msg: &mut wireguard)
        -> Result<Self, UnspecifiedCryptoFailure>
    {
        let initiator_chaining_key = pre.initiator_key;
        let c_r = pre.initiator_key;
        let h_r = pre.initiator_hash;
        let system = &mut this.system;

        // (Eprivr,Epubr):=DH-Generate()
        let (epriv_r, epub_r) = system.dh_generate();
        // msg.ephemeral:=Epubr
        let msg_ephemeral = msg.resp_ephemeral();
        msg_ephemeral.copy_from_slice(epub_r.as_bytes());
        // Cr:=Kdf1(Cr,Epubr)
        let c_r = system.kdf1(c_r, epub_r.as_bytes());
        // Hr:=Hash(Hr‖msg.ephemeral)
        let h_r = system.update_hash(h_r, msg_ephemeral);
        // Cr:=Kdf1(Cr,DH(Eprivr,Epubi))
        let c_r = {
            let dh = system.dh(&epriv_r, &pre.ephemeral_public);
            system.kdf1(c_r, dh.as_bytes())
        };
        // Cr:=Kdf1(Cr,DH(Eprivr,Spubi))
        let c_r = {
            let dh = system.dh(&epriv_r, &pre.initiator_public);
            system.kdf1(c_r, dh.as_bytes())
        };
        // FIXME!!!! What is Q.
        let q: NotSoSafeKey = unsafe { invoke_q() };
        // (Cr,τ,κ):=Kdf3(Cr,Q)
        let (c_r, t, k) = system.kdf3(c_r, &q);
        // Hr:=Hash(Hr‖τ)
        let h_r = system.update_hash(h_r, &t);
        // Hr:=Hash(Hr‖τ)
        let h_r = system.update_hash(h_r, &t);
        // msg.empty:=Aead(κ,0,,Hr)
        let msg_empty = msg.resp_empty();
        system.aead(
            &k,
            &mut CounterNonce::default(),
            &mut msg_empty[..],
            &h_r,
        )?;
        //Hr:=Hash(Hr‖msg.empty)
        let h_r = system.update_hash(h_r, msg_empty);

        let responder_chaining_key = c_r;

        let (initiator_send, initiator_recv) = system.kdf2(initiator_chaining_key, &[]);
        let (responder_send, responder_recv) = system.kdf2(responder_chaining_key, &[]);
        Ok(super::PostResponseHandshake {
            initiator_send,
            initiator_recv,
            responder_send,
            responder_recv,
        })
    }

    pub(crate) fn for_incoming(this: &mut super::This, pre: super::PostInitHandshake, msg: &mut wireguard)
        -> Result<Self, UnspecifiedCryptoFailure>
    {
        let initiator_chaining_key = pre.initiator_key;
        let c_r = pre.initiator_key;
        let h_r = pre.initiator_hash;
        let system = &mut this.system;
        // We must have a private key still.
        let epriv_i = pre.ephemeral_private.unwrap();
        // Epubr:=msg.ephemeral
        let msg_ephemeral = msg.resp_ephemeral();
        let epub_r: &[u8; 32] = TryFrom::try_from(&msg_ephemeral[..]).unwrap();
        let epub_r = PublicKey::from(*epub_r);
        // Cr:=Kdf1(Cr,Epubr)
        let c_r = system.kdf1(c_r, epub_r.as_bytes());
        // Hr:=Hash(Hr‖msg.ephemeral)
        let h_r = system.update_hash(h_r, msg_ephemeral);
        // Cr:=Kdf1(Cr,DH(Epubr,Eprivi))
        let c_r = {
            let dh = system.dh(&epriv_i, &epub_r);
            system.kdf1(c_r, dh.as_bytes())
        };
        // Cr:=Kdf1(Cr,DH(Epubr,Sprivi))
        let c_r = {
            let dh = system.dh(&this.private, &epub_r);
            system.kdf1(c_r, dh.as_bytes())
        };
        // FIXME!!!! What is Q.
        let q: NotSoSafeKey = unsafe { invoke_q() };
        // (Cr,τ,κ):=Kdf3(Cr,Q)
        let (c_r, t, k) = system.kdf3(c_r, &q);
        // Hr:=Hash(Hr‖τ)
        let h_r = system.update_hash(h_r, &t);
        // Aead(κ,0,,Hr):=msg.empty
        let msg_empty = msg.resp_empty();
        system.undo_aead(
            &k,
            &mut SlidingWindowNonce::default(),
            RawNonce::new(0),
            &mut msg_empty[..],
            &h_r,
        )?;
        //Hr:=Hash(Hr‖msg.empty)
        let h_r = system.update_hash(h_r, msg_empty);
        let responder_chaining_key = c_r;

        let (initiator_send, initiator_recv) = system.kdf2(initiator_chaining_key, &[]);
        let (responder_send, responder_recv) = system.kdf2(responder_chaining_key, &[]);
        Ok(super::PostResponseHandshake {
            initiator_send,
            initiator_recv,
            responder_send,
            responder_recv,
        })
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
            let dh = system.dh(&epriv_i, &pub_r);
            let mut kdf = system.kdf(&c_i, dh.as_bytes());
            (kdf.next().unwrap(), kdf.next().unwrap())
        };
        let mut counter = CounterNonce::default();
        msg_static = [0; 32+16];
        msg_static[..32].copy_from_slice(pub_i.as_bytes());
        system.aead(
            &k,
            &mut counter,
            &mut msg_static[..],
            &h_i
        ).unwrap();
        msg_static_key = k;
        msg_static_hash = h_i;

        let (c_i, k) = {
            let dh = system.dh(&priv_i, &pub_r);
            let mut kdf = system.kdf(&c_i, dh.as_bytes());
            (kdf.next().unwrap(), kdf.next().unwrap())
        };

        let mut counter = CounterNonce::default();
        // We don't check or send the timestamp, just the binding hash..
        msg_timestamp = [0; 12+16];
        system.aead(
            &k,
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
            &msg_static_key,
            &mut nonce,
            RawNonce::new(0),
            &mut msg_static,
            &msg_static_hash,
        ).expect("Unsealing static message failed");
        assert_eq!(&msg_static[..32], pub_i.as_bytes());

        let mut nonce = SlidingWindowNonce::default();
        system.undo_aead(
            &msg_timestamp_key,
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

        let c_r = system.kdf(&c_r, epub_r.as_bytes()).next().unwrap();
        rsp_eph = epub_r;

        let h_r = system.hash([&h_r[..], rsp_eph.as_bytes()].iter().cloned());
        let c_r = {
            let dh = system.dh(&priv_r, &epub_i);
            system.kdf(&c_r, dh.as_bytes()).next().unwrap()
        };
        let c_r = {
            let dh = system.dh(&epriv_r, &pub_i);
            system.kdf(&c_r, dh.as_bytes()).next().unwrap()
        };

        let (c_r, t, k) = {
            // Assuming definition of Q here..
            let q = system.dh(&epriv_r, &epub_i);
            let mut kdf = system.kdf(&c_r, q.as_bytes());
            rsp_q = q;

            (kdf.next().unwrap(), kdf.next().unwrap(), kdf.next().unwrap())
        };

        let h_r = system.hash([&h_r[..], &t[..]].iter().cloned());

        let mut counter = CounterNonce::default();
        rsp_empty = [0u8; 0+16];
        system.aead(
            &k,
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
            &rsp_empty_key,
            &mut nonce,
            RawNonce::new(0),
            &mut rsp_empty,
            &rsp_empty_hash,
        ).expect("Unsealing static message failed");
    }

    // Those would be used only when proceeding..
    let _ = (rsp_c, rsp_h, saved_epriv_r);
}
