use thiserror::Error;

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
