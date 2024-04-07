use argon2::{
    password_hash::{rand_core::CryptoRngCore, SaltString},
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
};
use arrayvec::ArrayString;
use diesel_async::RunQueryDsl;

use super::creds::{CredentialError, CredentialKey};
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

#[derive(Debug, Queryable, Insertable)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct User {
    id: Uuid,
    username: String,
    password: String,
    superuser: bool,
}

impl User {
    pub async fn create(
        db: &mut Connection,
        username: &Username,
        password: &Password,
        superuser: bool,
    ) -> Result<Uuid> {
        let id = Uuid::new_v4();
        let user = Self {
            id,
            username: username.to_string(),
            password: argon2()
                .hash_password(password.as_bytes(), &SaltString::generate(&mut rng()))
                .map_err(|err| {
                    error!(%err, "Error generating password hash for new user");
                    VerifyPasswordError
                })
                .context("Error generating password hash")?
                .to_string(),
            superuser,
        };

        user.insert_into(users::table)
            .execute(db)
            .await
            .context("Error inserting user into database")
            .map(|_| id)
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

    pub fn verify_password(&self, password: &Password) -> Result<(), VerifyPasswordError> {
        argon2()
            .verify_password(
                password.as_bytes(),
                &PasswordHash::new(&self.password).map_err(|_| VerifyPasswordError)?,
            )
            .map_err(|_| VerifyPasswordError)
    }

    pub fn get_credential_key(
        &self,
        password: &Password,
    ) -> Result<CredentialKey, CredentialError> {
        self.verify_password(password)
            .map_err(|VerifyPasswordError| CredentialError::Unauthorized)?;
        unsafe { CredentialKey::derive_for_auth(password, ()) }
    }
}
