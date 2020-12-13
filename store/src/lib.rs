use anyhow::Result;
use async_std::path::{
    Path,
    PathBuf,
};
use generic_array::typenum::U32;
use keystore::KeyStore as KeyPair;
use secrecy::{
    ExposeSecret,
    SecretString,
};
use sled::{
    transaction::TransactionError,
    IVec,
    Transactional,
    Tree,
};
mod arr;
mod err;
use arr::SafeArray;
use err::{
    DbError,
    IncorrectPassword,
    Locked,
    OldDNECurrent,
    PasswordNotSet,
    PasswordSet,
    PasswordTooSimple,
};
use gen::score;

pub struct Db {
    db: sled::Db,
    pub keys: Vec<Vec<u8>>,
}

impl Db {
    pub fn new<T: AsRef<Path>>(path: T) -> Self {
        Db {
            // TODO: use config to ensure fresh path
            // TODO2: propagate error properly instead of this raw unwrap
            db: sled::open(path.as_ref().to_path_buf()).unwrap(),
            keys: Vec::new(),
        }
    }
}

/// Password authenticated store
pub struct Store {
    locked: bool,
    db: Db,
    key: KeyPair,
    password: Option<SecretString>,
}

impl Store {
    pub fn new<T: AsRef<Path>>(path: T) -> Self {
        Self {
            locked: false,
            db: Db::new(path),
            key: KeyPair::new(),
            password: None,
        }
    }
    pub fn set_password(&mut self, password: SecretString) -> Result<()> {
        ensure!(!self.has_password(), PasswordSet);
        ensure!(
            score(password.expose_secret().to_string()) >= 10u8,
            PasswordTooSimple
        );
        self.password = Some(password);
        Ok(())
    }
    pub fn has_password(&self) -> bool {
        self.password.is_some()
    }
    pub fn change_password(
        &mut self,
        old: SecretString,
        new: SecretString,
    ) -> Result<()> {
        ensure!(self.has_password(), PasswordNotSet);
        let current = &self
            .password
            .as_ref()
            .expect("checked existence in line above");
        ensure!(
            current.expose_secret() == old.expose_secret(),
            IncorrectPassword
        );
        ensure!(
            score(new.expose_secret().to_string()) >= 10u8,
            PasswordTooSimple
        );
        self.password = Some(new);
        Ok(())
    }
}

pub trait CredentialStore<Key, Credentials> {
    fn keys(&self) -> Result<Vec<Key>>;
    // first check existence in keyset, then check the db
    fn get(&self, key: Key) -> Result<Credentials>;
    // first time inserting a credential
    fn insert(&mut self, key: Key, cred: Credentials) -> Result<()>;
    // to update credentials
    fn cas(
        &mut self,
        key: Key,
        old: Credentials,
        new: Credentials,
    ) -> Result<()>;
}

// TODO: change IVec to SafeArray<U32>
impl CredentialStore<Vec<u8>, IVec> for Store {
    fn keys(&self) -> Result<Vec<Vec<u8>>> {
        ensure!(!self.locked, Locked);
        Ok(self.db.keys.clone())
    }
    fn get(&self, key: Vec<u8>) -> Result<IVec> {
        ensure!(!self.locked, Locked);
        ensure!(self.db.keys.contains(&key), DbError::KeyDNE);
        if let Ok(Some(v)) = self.db.db.get(key) {
            Ok(v)
        } else {
            Err(DbError::ValueDNE.into())
        }
    }
    fn insert(&mut self, key: Vec<u8>, cred: IVec) -> Result<()> {
        ensure!(!self.locked, Locked);
        ensure!(
            !self.db.keys.contains(&key),
            DbError::CannotInsertIfValExists
        );
        self.db.keys.push(key.clone());
        self.db.db.insert(key, cred)?;
        Ok(())
    }
    fn cas(&mut self, key: Vec<u8>, old: IVec, new: IVec) -> Result<()> {
        let k = self.get(key.clone())?;
        if k == old {
            self.db.db.insert(key, new)?;
            Ok(())
        } else {
            Err(OldDNECurrent.into())
        }
    }
}

pub trait Lockable<Password> {
    fn unlocked(&self) -> bool;
    fn unlock(&mut self, code: Password) -> Result<()>;
    fn lock(&mut self) -> Result<()>;
}

impl Lockable<SecretString> for Store {
    fn unlocked(&self) -> bool {
        !self.locked
    }
    fn unlock(&mut self, code: SecretString) -> Result<()> {
        ensure!(self.has_password(), PasswordNotSet);
        let word = &self
            .password
            .as_ref()
            .expect("checked existence in line above");
        ensure!(
            word.expose_secret() == code.expose_secret(),
            IncorrectPassword
        );
        self.locked = false;
        Ok(())
    }
    fn lock(&mut self) -> Result<()> {
        ensure!(self.has_password(), PasswordNotSet);
        self.locked = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn storage_initialization_respects_password_settings() {
        let mut s = Store::new("nxn1");
        // 1 -- Storage Initialized
        let p1 = SecretString::new("examplecode".to_string());
        let xa = s.set_password(p1.clone());
        // 2 -- Password Set for Storage
        assert!(xa.is_ok());
        let p2 = SecretString::new("examplezcode".to_string());
        let xb = s.set_password(p2.clone());
        // 3 -- Password was not Set because Already Set
        assert!(xb.is_err());
        let xc = s.change_password(p1.clone(), p2.clone());
        // 4 -- Password was Changed Because Old was Correct
        assert!(xc.is_ok());
        let xd = s.change_password(p1.clone(), p1);
        // 5 -- Password Change Failed Because Old Was Incorrect
        assert!(xd.is_err());
        let xe = s
            .change_password(p2, SecretString::new("examplexcode".to_string()));
        // 6 -- Password Change Succeeded Because Old Was Correct
        assert!(xe.is_ok());
    }
    #[test]
    fn lock_unlock_functionality() {
        let mut s = Store::new("nxn2");
        // 1 -- Cannot lock if password is not set
        assert!(s.lock().is_err());
        let xa = s.set_password(SecretString::new("examplecode".to_string()));
        // 2 -- Password Set for Storage
        assert!(xa.is_ok());
        // 3 -- Lock succeeds because password is set
        assert!(s.lock().is_ok());
        // 4 - Unlock fails with the incorrect passcode
        assert!(s
            .unlock(SecretString::new("examplezcode".to_string()))
            .is_err());
        let xc = s.change_password(
            SecretString::new("examplecode".to_string()),
            SecretString::new("examplezcode".to_string()),
        );
        // 5 -- Password was Changed Because Old was Correct
        assert!(xc.is_ok());
        // 6 - Unlock succeeds with the now correct passcode
        assert!(s
            .unlock(SecretString::new("examplezcode".to_string()))
            .is_ok());
    }
}
