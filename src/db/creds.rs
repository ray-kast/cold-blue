use super::user::{self, Password};
use crate::prelude::*;

#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    #[error("Internal error processing credentials")]
    Internal,
    #[error("Unauthorized credentials operation")]
    Unauthorized,
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
    pub unsafe fn generate(password: &Password) -> Result<(Self, CredentialKeyParams), CredentialError> {
        todo!()
    }

    // TODO: zeroize
    pub unsafe fn derive_for_auth(
        password: &Password,
        params: (),
    ) -> Result<Self, CredentialError> {
        let mut key = [0_u8; KEY_SIZE];
        // // TODO: !!!!store and use fixed argon2 parameters!!!!
        // user::argon2()
        //     .hash_password_into(password.as_bytes(), &params.salt, &mut key)
        //     .map_err(|err| {
        //         error!(%err, "Error deriving key with argon2");
        //         CredentialError::Internal
        //     })?;
        error!("KEY DERIVATION IS NOT IMPLEMENTED. DO NOT TRUST.");

        Ok(Self(key))
    }

    #[inline]
    pub unsafe fn into_inner(self) -> [u8; KEY_SIZE] { self.0 }
}

pub struct Creds {}
