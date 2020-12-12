//! [SRC](https://github.com/sunshine-protocol/sunshine-core/blob/master/crypto/src/array.rs)
use async_std::task;
use generic_array::{
    ArrayLength,
    GenericArray,
};
use parity_scale_codec::{
    Decode,
    Encode,
    Input,
};
use rand::{
    thread_rng,
    Rng,
};
use secrecy::{
    ExposeSecret,
    SecretString,
    SecretVec,
};
use std::fmt::Debug;
use strobe_rs::{
    SecParam,
    Strobe,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Async Random Byte Generator
async fn random<T: Default + AsMut<[u8]> + Send + 'static>() -> T {
    task::spawn_blocking(|| {
        let mut buf = T::default();
        thread_rng().fill(buf.as_mut());
        buf
    })
    .await
}

#[derive(Debug)]
pub struct InsufficientEntropy;
#[derive(Debug)]
pub struct SizeMismatch;

pub trait Size:
    ArrayLength<u8> + Debug + Default + Eq + Send + Sync + 'static
{
}
impl<T: ArrayLength<u8> + Debug + Default + Eq + Send + Sync + 'static> Size
    for T
{
}

/// A wrapper around a generic array providing cryptographic functions.
///
/// Safe to use for secrets. It is zeroized on drop and has a "safe" `Debug` implementation
/// and comparisons happen in constant time.
#[derive(Clone, Default, Hash)]
#[allow(clippy::derive_hash_xor_eq)]
pub struct SafeArray<S: Size>(GenericArray<u8, S>);

impl<S: Size> core::fmt::Debug for SafeArray<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{}", std::any::type_name::<Self>())
    }
}

impl<S: Size> Drop for SafeArray<S> {
    fn drop(&mut self) {
        self.0.zeroize()
    }
}

impl<S: Size> AsRef<[u8]> for SafeArray<S> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<S: Size> AsMut<[u8]> for SafeArray<S> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl<S: Size> PartialEq for SafeArray<S> {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref().ct_eq(other.as_ref()).into()
    }
}

impl<S: Size> Eq for SafeArray<S> {}

impl<S: Size> Encode for SafeArray<S> {
    fn size_hint(&self) -> usize {
        S::to_usize()
    }

    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        f(self.as_ref())
    }
}

impl<S: Size> Decode for SafeArray<S> {
    fn decode<R: Input>(
        value: &mut R,
    ) -> Result<Self, parity_scale_codec::Error> {
        let mut ab = Self::default();
        value.read(ab.as_mut())?;
        Ok(ab)
    }
}

impl<S: Size> SafeArray<S> {
    pub fn new(data: GenericArray<u8, S>) -> Self {
        Self(data)
    }

    pub async fn random() -> Self {
        random().await
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, SizeMismatch> {
        if bytes.len() != S::to_usize() {
            return Err(SizeMismatch)
        }
        let mut ab = Self::default();
        ab.copy_from_slice(bytes);
        Ok(ab)
    }

    pub fn from_mnemonic(
        mnemonic: &bip39::Mnemonic,
    ) -> Result<Self, InsufficientEntropy> {
        let mut res = Self::default();
        let entropy = mnemonic.to_entropy();
        if entropy.len() < res.size() {
            return Err(InsufficientEntropy)
        }
        res.copy_from_slice(&entropy[..res.size()]);
        Ok(res)
    }

    pub fn copy_from_slice(&mut self, slice: &[u8]) {
        self.as_mut().copy_from_slice(slice);
    }

    pub fn size(&self) -> usize {
        S::to_usize()
    }

    pub fn xor(&self, other: &Self) -> Self {
        let mut res = Self::default();
        let a = self.as_ref();
        let b = other.as_ref();
        for i in 0..res.size() {
            res.as_mut()[i] = a[i] ^ b[i]
        }
        res
    }

    pub fn kdf(input: &SecretString) -> Self {
        let mut s = Strobe::new(b"DiscoKDF", SecParam::B128);
        s.ad(input.expose_secret().as_bytes(), false);
        let mut res = Self::default();
        s.prf(res.as_mut(), false);
        res
    }

    pub fn hash(input: &[u8]) -> Self {
        let mut s = Strobe::new(b"DiscoHash", SecParam::B128);
        s.ad(input, false);
        let mut res = Self::default();
        s.prf(res.as_mut(), false);
        res
    }

    pub fn array(&self) -> &GenericArray<u8, S> {
        &self.0
    }

    pub fn to_vec(&self) -> SecretVec<u8> {
        SecretVec::new(self.0.as_ref().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use generic_array::typenum::U32;

    #[async_std::test]
    async fn test_enc_dec() -> std::io::Result<()> {
        let key = SafeArray::<U32>::random().await;
        let key2 = SafeArray::<U32>::decode(&mut &key.encode()[..]).unwrap();
        assert_eq!(key, key2);
        Ok(())
    }
}
