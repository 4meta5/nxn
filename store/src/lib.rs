use anyhow::Result;
use async_std::path::{
    Path,
    PathBuf,
};
use secrecy::{
    ExposeSecret,
    SecretString,
};
mod err;
use err::{
    IncorrectPassword,
    PasswordNotSet,
    PasswordSet,
    PasswordTooSimple,
};
use gen::score;

/// Password authenticated store
pub struct Store {
    path: PathBuf,
    password: Option<SecretString>,
}

impl Store {
    pub fn new<T: AsRef<Path>>(path: T) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            password: None,
        }
    }
    pub fn set_password(&mut self, password: SecretString) -> Result<()> {
        if self.has_password() {
            Err(PasswordSet.into())
        } else {
            if score(password.expose_secret().to_string()) < 10u8 {
                return Err(PasswordTooSimple.into())
            }
            self.password = Some(password);
            Ok(())
        }
    }
    pub fn has_password(&self) -> bool {
        self.password.is_some()
    }
    pub fn change_password(
        &mut self,
        old: SecretString,
        new: SecretString,
    ) -> Result<()> {
        if let Some(p) = &self.password {
            if p.expose_secret() == old.expose_secret() {
                if score(new.expose_secret().to_string()) < 10u8 {
                    return Err(PasswordTooSimple.into())
                }
                self.password = Some(new);
                Ok(())
            } else {
                Err(IncorrectPassword.into())
            }
        } else {
            Err(PasswordNotSet.into())
        }
    }
}

#[test]
fn password_behaves() {
    let mut s = Store::new("example");
    // 1 -- Storage Initialized
    let p1 = SecretString::new("examplecode".to_string());
    let a = s.set_password(p1.clone());
    // 2 -- Password Set for Storage
    assert!(a.is_ok());
    let p2 = SecretString::new("examplezcode".to_string());
    let b = s.set_password(p2.clone());
    // 3 -- Password was not Set because Already Set
    assert!(b.is_err());
    let c = s.change_password(p1.clone(), p2.clone());
    // 4 -- Password was Changed Because Old was Correct
    assert!(c.is_ok());
    let d = s.change_password(p1.clone(), p1);
    // 5 -- Password Change Failed Because Old Was Incorrect
    assert!(d.is_err());
    let e = s.change_password(
        p2.clone(),
        SecretString::new("examplexcode".to_string()),
    );
    // 6 -- Password Change Succeeded Because Old Was Correct
    assert!(e.is_ok());
}
