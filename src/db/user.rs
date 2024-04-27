use argon2::{
    password_hash::{rand_core::CryptoRngCore, SaltString},
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
};
use arrayvec::ArrayString;

use super::credentials::{
    Credential, CredentialError, CredentialKeyParams, CredentialManager, CredentialView,
    UserCredentialKey,
};
use crate::{db::prelude::*, prelude::*};

#[derive(Debug, thiserror::Error)]
#[error("Password verification failed")]
pub struct VerifyPasswordError;

// Since I plan to use Argon2 the password should be limited to avoid DoS
pub const MAX_USERNAME_LEN: usize = 512;
pub const MAX_PASSWORD_LEN: usize = 512;

pub type Username = ArrayString<MAX_USERNAME_LEN>;
// TODO: zeroize
pub type Password = ArrayString<MAX_PASSWORD_LEN>;

#[inline]
pub fn argon2() -> Argon2<'static> { Argon2::default() }

// TODO: choose a different rng?
#[inline]
pub fn rng() -> impl CryptoRngCore { argon2::password_hash::rand_core::OsRng }

#[derive(Queryable, Insertable)]
#[diesel(check_for_backend(Pg))]
pub struct User {
    id: Uuid,
    username: String,
    password: String,
    superuser: bool,
    key_params: CredentialKeyParams,
}

impl User {
    pub async fn create(
        db: &mut Connection,
        username: &Username,
        password: &Password,
        superuser: bool,
    ) -> Result<Self> {
        let id = Uuid::new_v4();
        let user = Self {
            id,
            username: username.to_string(),
            password: argon2()
                .hash_password(password.as_bytes(), &SaltString::generate(&mut rng()))
                .erase_err_disp(
                    "Error generating password hash for new user",
                    VerifyPasswordError,
                )
                .context("Error generating password hash")?
                .to_string(),
            superuser,
            key_params: CredentialKeyParams::generate(),
        };

        (&user)
            .insert_into(users::table)
            .execute(db)
            .await
            .context("Error inserting user into database")?;

        Ok(user)
    }

    pub async fn from_id(db: &mut Connection, id: &Uuid) -> Result<Option<Self>> {
        users::table
            .filter(users::id.eq(id))
            .first(db)
            .await
            .optional()
            .context("Error querying users by ID")
    }

    pub async fn from_username(db: &mut Connection, name: &str) -> Result<Option<Self>> {
        users::table
            .filter(users::username.eq(name))
            .first(db)
            .await
            .optional()
            .context("Error querying users by username")
    }

    #[inline]
    pub fn id(&self) -> &Uuid { &self.id }

    #[inline]
    pub(super) fn key_params(&self) -> &CredentialKeyParams { &self.key_params }

    pub fn verify_password(&self, password: &Password) -> Result<(), VerifyPasswordError> {
        argon2()
            .verify_password(
                password.as_bytes(),
                &PasswordHash::new(&self.password)
                    .erase_err_disp("Error parsing password hash", VerifyPasswordError)?,
            )
            .erase_err_disp("Error verifying password", VerifyPasswordError)
    }

    pub async fn list_credentials(&self, db: &mut Connection) -> Result<Vec<CredentialView>> {
        Ok(credentials::table
            .filter(credentials::owner.eq(self.id))
            .load(db)
            .await
            .context("Error querying credentials for user")?
            .into_iter()
            .map(|c: Credential| c.to_view())
            .collect())
    }

    #[inline]
    pub fn derive_credential_key(
        &self,
        mgr: &CredentialManager,
        password: &Password,
    ) -> Result<UserCredentialKey, CredentialError> {
        mgr.derive_user_key(self, password)
    }
}
