use super::user::{self, Password};
use crate::prelude::*;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
#[repr(transparent)]
pub struct CredentialError(#[from] ErrorInner);

#[derive(Debug, thiserror::Error)]
enum ErrorInner {
    #[error("Error in generate")]
    Generate,
    #[error("Error in derive_for_auth")]
    DeriveForAuth,
}

const KEY_SIZE: usize = 32;

// TODO: zeroize
#[repr(transparent)]
pub struct CredentialKey([u8; KEY_SIZE]);

// TODO: zeroize
pub struct CredentialKeyParams {
    // TODO
    salt: Vec<u8>,
}

impl CredentialKey {
    pub fn generate(password: &Password) -> Result<(Self, CredentialKeyParams), CredentialError> {
        todo!()
    }

    // TODO: zeroize
    pub fn derive_for_auth(
        password: &Password,
        params: &CredentialKeyParams,
    ) -> Result<Self, CredentialError> {
        let mut key = [0_u8; KEY_SIZE];
        // TODO: !!!!store and use fixed argon2 parameters!!!!
        user::argon2()
            .hash_password_into(password.as_bytes(), &params.salt, &mut key)
            .map_err(|err| {
                error!(%err, "Error deriving key with argon2");
                CredentialError(ErrorInner::DeriveForAuth)
            })?;

        Ok(Self(key))
    }

    #[inline]
    pub unsafe fn into_inner(self) -> [u8; KEY_SIZE] { self.0 }
}

pub struct Creds {}
