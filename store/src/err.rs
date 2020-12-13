use thiserror::Error;

#[macro_export]
macro_rules! ensure {
    ( $x:expr, $y:expr $(,)? ) => {{
        if !$x {
            return Err($y.into())
        }
    }};
}

#[derive(Debug, Error)]
#[error("Suggested Password Was Too Simple")]
pub struct PasswordTooSimple;

#[derive(Debug, Error)]
#[error("Password Not Set, Must Set Initial Password Before Changing It")]
pub struct PasswordNotSet;

#[derive(Debug, Error)]
#[error("Password Already Set, Must Use Old Password to Change")]
pub struct PasswordSet;

#[derive(Debug, Error)]
#[error("Password Submission Did Not Match Record")]
pub struct IncorrectPassword;

#[derive(Debug, Error)]
#[error("Credential Cannot Be Read When Store Is Locked")]
pub struct Locked;

#[derive(Debug, Error)]
#[error("CAS Requires Valid Comparison Between Old and Existing Entry")]
pub struct OldDNECurrent;

#[derive(Debug, Error)]
pub enum DbError {
    #[error(transparent)]
    SledError(#[from] sled::Error),
    #[error("Key Does Not Exist in Key Set")]
    KeyDNE,
    #[error("Insert Is Only For Fresh Keys")]
    CannotInsertIfValExists,
    #[error("Value Not Found For Provided Key")]
    ValueDNE,
}

#[derive(Debug, Error)]
pub enum KeyPairError {
    #[error(transparent)]
    AeadError(#[from] aes_gcm_siv::aead::Error),
    #[error(transparent)]
    Bip39Error(#[from] bip39::Error),
    #[error("Empty Seed Provided")]
    EmptySeed,
}
