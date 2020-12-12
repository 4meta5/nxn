//! [SRC](https://github.com/owlchat/keystore/blob/master/keystore/src/lib.rs)
use crate::err::KeyPairError;
use aes_gcm_siv::{
    aead::{
        AeadInPlace,
        Buffer,
        NewAead,
    },
    Aes256GcmSiv,
};
use bip39::Mnemonic;
use rand::{
    rngs::OsRng,
    Rng,
};
use std::convert::TryFrom;
use x25519_dalek::{
    PublicKey,
    StaticSecret as SecretKey,
};
use zeroize::Zeroize;

/// KeyPair ([`PublicKey`], [`SecretKey`])
/// which holds the `Seed` used to generate the [`SecretKey`]
pub struct KeyPair {
    pk: PublicKey,
    sk: SecretKey,
    seed: Option<[u8; 32]>,
}

impl KeyPair {
    /// Create a new `KeyPair`.
    /// ### Note
    /// After creating a new `KeyPair`, call [`KeyPair::secret_key`] to get your [`SecretKey`]
    /// and [`KeyPair::seed`] to get the `Seed` used in creating that private keys.
    /// Those two `[u8; u32]` arrays should be stored securely in the device [`iOS KeyChain`][1] or [`Android KeyPair`][2].
    ///
    /// [1]: https://developer.apple.com/documentation/security/keychain_services
    /// [2]: https://developer.android.com/training/articles/KeyStore.html
    pub fn new() -> Self {
        let mut seed = [0u8; 32];
        let mut rnd = OsRng::default();
        rnd.fill(&mut seed);
        let sk = SecretKey::from(seed);
        let pk = PublicKey::from(&sk);
        let ks = Self {
            pk,
            sk,
            seed: Some(seed),
        };
        seed.zeroize();
        ks
    }

    /// Init the `KeyPair` with existing SecretKey Bytes.
    /// ### Note
    /// The created `KeyPair` does not contain any seed.
    pub fn init(mut secret_key: [u8; 32]) -> Self {
        let sk = SecretKey::from(secret_key); // copy
        let pk = PublicKey::from(&sk);
        // so we zeroize the last copy here before dropping it.
        secret_key.zeroize();
        Self { pk, sk, seed: None }
    }

    /// Get your [`PublicKey`] as bytes.
    pub fn public_key(&self) -> [u8; 32] {
        self.pk.to_bytes()
    }

    /// Get your [`SecretKey`] as bytes.
    pub fn secret_key(&self) -> [u8; 32] {
        self.sk.to_bytes()
    }

    /// Get your `Seed` as bytes (if any).
    ///
    /// ### Note
    /// Only Available for a newly created `KeyPair`.
    pub fn seed(&self) -> Option<[u8; 32]> {
        self.seed
    }

    /// Create a [`Mnemonic`] Backup from the provided seed as `String`.
    ///
    /// if this a newly created `KeyStroe` you could pass `None` since it will use the current seed.
    /// it will return Error if both the current seed and the provided one is both `None`.
    pub fn backup(
        &self,
        seed: Option<[u8; 32]>,
    ) -> Result<String, KeyPairError> {
        let seed = self.seed.or(seed).ok_or(KeyPairError::EmptySeed)?;
        let mnemonic = Mnemonic::from_entropy(&seed)?;
        Ok(mnemonic.to_string())
    }

    /// Restore a `KeyPair` from a [`Mnemonic`] Paper Backup.
    ///
    /// The new `KeyPair` will also contain the `Seed` used to create the [`SecretKey`].
    /// See [`KeyPair::new`] for the following steps after creating a new KeyPair.
    pub fn restore(paper_key: String) -> Result<Self, KeyPairError> {
        let mnemonic = Mnemonic::parse(paper_key)?;
        let entropy = mnemonic.to_entropy();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&entropy);
        let sk = SecretKey::from(seed);
        let pk = PublicKey::from(&sk);
        let ks = Self {
            pk,
            sk,
            seed: Some(seed),
        };
        seed.zeroize();
        Ok(ks)
    }

    /// Perform a Diffie-Hellman to derive `SharedSecret`.
    pub fn dh(&self, their_public: [u8; 32]) -> [u8; 32] {
        let their_public = PublicKey::from(their_public);
        let shared_secret = self.sk.diffie_hellman(&their_public);
        shared_secret.to_bytes()
    }

    pub fn encrypt<B: Buffer>(&self, data: &mut B) -> Result<(), KeyPairError> {
        let mut sk = self.sk.to_bytes();
        self.encrypt_with(sk, data)?;
        sk.zeroize();
        Ok(())
    }

    pub fn decrypt<B: Buffer>(&self, data: &mut B) -> Result<(), KeyPairError> {
        let mut sk = self.sk.to_bytes();
        self.decrypt_with(sk, data)?;
        sk.zeroize();
        Ok(())
    }

    pub fn encrypt_with<B: Buffer>(
        &self,
        mut sk: [u8; 32],
        data: &mut B,
    ) -> Result<(), KeyPairError> {
        let mut rnd = OsRng::default();
        let mut nonce = [0u8; 12];
        rnd.fill(&mut nonce);
        aes_encrypt(&sk, &nonce, data)?;
        data.extend_from_slice(&nonce)?;
        sk.zeroize();
        Ok(())
    }

    pub fn decrypt_with<B: Buffer>(
        &self,
        mut sk: [u8; 32],
        data: &mut B,
    ) -> Result<(), KeyPairError> {
        const NONCE_LEN: usize = 12;
        if data.len() < NONCE_LEN {
            return Err(KeyPairError::AeadError(aes_gcm_siv::aead::Error))
        }
        let mut nonce = [0u8; NONCE_LEN];
        let other = data.as_ref().iter().rev().take(NONCE_LEN);
        nonce.iter_mut().rev().zip(other).for_each(|(v, b)| *v = *b);
        // remove the nonce, we got it now.
        data.truncate(data.as_ref().len() - NONCE_LEN);
        aes_decrypt(&sk, &nonce, data)?;
        sk.zeroize();
        Ok(())
    }
}

impl Default for KeyPair {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

impl From<[u8; 32]> for KeyPair {
    fn from(mut sk: [u8; 32]) -> Self {
        let ks = Self::init(sk);
        sk.zeroize();
        ks
    }
}

impl TryFrom<String> for KeyPair {
    type Error = KeyPairError;
    fn try_from(paper_key: String) -> Result<Self, Self::Error> {
        Self::restore(paper_key)
    }
}

fn aes_decrypt<B: Buffer>(
    key: &[u8],
    nonce: &[u8],
    data: &mut B,
) -> Result<(), KeyPairError> {
    let cipher = Aes256GcmSiv::new(key.into());
    cipher
        .decrypt_in_place(nonce.into(), b"", data)
        .map_err(Into::into)
}

fn aes_encrypt<B: Buffer>(
    key: &[u8],
    nonce: &[u8],
    data: &mut B,
) -> Result<(), KeyPairError> {
    let cipher = Aes256GcmSiv::new(key.into());
    cipher
        .encrypt_in_place(nonce.into(), b"", data)
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        let ks = KeyPair::new();
        let mut data = Vec::with_capacity((8 + 12) * 4);
        data.extend_from_slice(b"Owlchat");
        ks.encrypt(&mut data).expect("ecnrypt");
        let original = b"Owlchat".to_vec();
        assert_ne!(data, original);
        ks.decrypt(&mut data).expect("decrypt");
        assert_eq!(data, original);
    }

    #[test]
    fn keypair_init() {
        let ks = KeyPair::new();
        let mut data = Vec::with_capacity((8 + 12) * 4);
        data.extend_from_slice(b"Owlchat");
        let original = b"Owlchat".to_vec();
        ks.encrypt(&mut data).unwrap();
        let sk = ks.secret_key();
        drop(ks);
        let ks = KeyPair::init(sk);
        ks.decrypt(&mut data).unwrap();
        assert_eq!(data, original);
    }
    #[test]
    fn same_shared_secret() {
        let alice_ks = KeyPair::new();
        let bob_ks = KeyPair::new();

        let alice_sk = alice_ks.dh(bob_ks.public_key());
        let bob_sk = bob_ks.dh(alice_ks.public_key());
        assert_eq!(alice_sk, bob_sk);
    }

    #[test]
    fn funny_conversation() {
        let alice_ks = KeyPair::new();
        let bob_ks = KeyPair::new();

        let alice_sk = alice_ks.dh(bob_ks.public_key());
        let bob_sk = bob_ks.dh(alice_ks.public_key());

        let mut m0 = Vec::with_capacity((12 + 12) * 4);
        m0.extend_from_slice(b"Knock, knock");
        let original = b"Knock, knock".to_vec();
        alice_ks.encrypt_with(alice_sk, &mut m0).unwrap();
        bob_ks.decrypt_with(bob_sk, &mut m0).unwrap();
        assert_eq!(original, m0);

        let mut m1 = Vec::with_capacity((12 + 12) * 4);
        m1.extend_from_slice(b"Who's there?");
        let original = b"Who's there?".to_vec();
        bob_ks.encrypt_with(bob_sk, &mut m1).unwrap();
        alice_ks.decrypt_with(alice_sk, &mut m1).unwrap();
        assert_eq!(original, m1);
    }

    #[test]
    fn backup_and_restore() {
        let ks = KeyPair::new();
        let paper_key = ks.backup(None).unwrap();
        println!("Backup Paper Key: {}", paper_key);
        let mut data = Vec::with_capacity((8 + 12) * 4);
        data.extend_from_slice(b"Owlchat");
        let original = b"Owlchat".to_vec();
        ks.encrypt(&mut data).unwrap();
        drop(ks);

        let ks = KeyPair::restore(paper_key).unwrap();
        ks.decrypt(&mut data).unwrap();
        assert_eq!(original, data);
    }
}
