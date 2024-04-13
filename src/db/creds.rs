use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit,
};
use diesel::{
    backend::Backend, deserialize, expression::AsExpression,
    query_builder::bind_collector::RawBytesBindCollector, serialize, sql_types::Text,
};
use rand::RngCore;

use self::payload::Named;

use super::user::{rng, Password, User, VerifyPasswordError};
use crate::{db::prelude::*, prelude::*};

mod payload;

pub use payload::{AtProtoCredential, AtProtoCredentialForm, CredentialBuilder};

#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    #[error("Internal error processing credentials")]
    Internal,
    #[error("Unauthorized credentials operation")]
    Unauthorized,
}

#[derive(Clone)]
#[repr(transparent)]
pub struct CredentialManager(Arc<CredentialManagerInternal>);

struct CredentialManagerInternal {
    key_secret: [u8; argon2::RECOMMENDED_SALT_LEN],
}

impl CredentialManager {
    pub fn new(key_secret: &str) -> Result<Self> {
        let key_secret = {
            use base64::prelude::*;

            BASE64_STANDARD
                .decode(key_secret)
                .context("Error decoding base64 credential key secret")?
                .try_into()
                .map_err(|v: Vec<_>| {
                    anyhow!(
                        "Invalid length {} for credential key secret, expected {}",
                        v.len(),
                        argon2::RECOMMENDED_SALT_LEN
                    )
                })?
        };

        Ok(Self(CredentialManagerInternal { key_secret }.into()))
    }

    // TODO: zeroize
    pub fn derive_user_key<'a>(
        &self,
        user: &'a User,
        password: &Password,
    ) -> Result<UserCredentialKey<'a>, CredentialError> {
        user.verify_password(password)
            .map_err(|VerifyPasswordError| CredentialError::Unauthorized)?;
        let key = unsafe { derive(&self.0, user.key_params(), password.as_bytes()) }?;
        Ok(UserCredentialKey(user, CredentialKey(key)))
    }
}

// TODO: test this !!!!
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Argon2Params {
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    output_len: Option<usize>,
}

impl From<argon2::Params> for Argon2Params {
    fn from(value: argon2::Params) -> Self {
        Self {
            m_cost: value.m_cost(),
            t_cost: value.t_cost(),
            p_cost: value.p_cost(),
            output_len: value.output_len(),
        }
    }
}

impl TryFrom<Argon2Params> for argon2::Params {
    type Error = argon2::Error;

    fn try_from(value: Argon2Params) -> Result<Self, Self::Error> {
        let Argon2Params {
            m_cost,
            t_cost,
            p_cost,
            output_len,
        } = value;
        Self::new(m_cost, t_cost, p_cost, output_len)
    }
}

// TODO: zeroize
#[serde_with::serde_as]
#[derive(Debug, AsExpression, deserialize::FromSqlRow, serde::Serialize, serde::Deserialize)]
#[diesel(sql_type = Text)]
pub struct CredentialKeyParams {
    #[serde_as(as = "serde_with::DisplayFromStr")]
    algorithm: argon2::Algorithm,
    #[serde_as(as = "serde_with::TryFromInto<u32>")]
    version: argon2::Version,
    #[serde_as(as = "serde_with::TryFromInto<Argon2Params>")]
    params: argon2::Params,
    #[serde_as(as = "serde_with::base64::Base64")]
    salt: [u8; argon2::RECOMMENDED_SALT_LEN],
}

impl CredentialKeyParams {
    #[must_use]
    pub fn generate() -> Self {
        let mut salt = [0_u8; argon2::RECOMMENDED_SALT_LEN];
        rng().fill_bytes(&mut salt);

        Self {
            algorithm: argon2::Algorithm::default(),
            version: argon2::Version::default(),
            params: argon2::Params::default(),
            salt,
        }
    }
}

impl<B: Backend> deserialize::FromSql<Text, B> for CredentialKeyParams
where String: deserialize::FromSql<Text, B>
{
    fn from_sql(bytes: <B as Backend>::RawValue<'_>) -> deserialize::Result<Self> {
        let s = <String as deserialize::FromSql<Text, B>>::from_sql(bytes)?;
        ron::from_str(&s).map_err(Into::into)
    }
}

impl<B> serialize::ToSql<Text, B> for CredentialKeyParams
where
    for<'c> B: Backend<BindCollector<'c> = RawBytesBindCollector<B>>,
    String: serialize::ToSql<Text, B>,
{
    fn to_sql<'b>(&'b self, out: &mut serialize::Output<'b, '_, B>) -> serialize::Result {
        let s = ron::to_string(&self)?;
        <String as serialize::ToSql<Text, B>>::to_sql(&s, &mut out.reborrow())
    }
}

const KEY_SIZE: usize = 32;

// TODO: zeroize
#[repr(transparent)]
pub struct CredentialKey([u8; KEY_SIZE]);

// TODO: test
// TODO: make all my usages of argon2 consistent
// TODO: should LEN be a const?
unsafe fn derive<'a, const LEN: usize>(
    mgr: &'a CredentialManagerInternal,
    params: &'a CredentialKeyParams,
    password: &'a [u8],
) -> Result<[u8; LEN], CredentialError> {
    let CredentialKeyParams {
        algorithm,
        version,
        ref params,
        ref salt,
    } = *params;

    let param_len = params.output_len().unwrap_or(LEN);

    if param_len != LEN {
        error!(%LEN, %param_len, "output_len of key derivation parameters did not match LEN");
        return Err(CredentialError::Internal);
    }

    let mut hash = [0_u8; LEN];
    argon2::Argon2::new_with_secret(&mgr.key_secret, algorithm, version, params.clone())
        .map_err(|_| CredentialError::Internal)?
        .hash_password_into(password, salt, &mut hash)
        .map_err(|_| CredentialError::Internal)?;

    Ok(hash)
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct UserCredentialClaims {
    id: Uuid,
    // TODO: zeroize
    key: [u8; KEY_SIZE],
}

impl UserCredentialClaims {
    #[inline]
    pub fn id(&self) -> &Uuid { &self.id }

    pub fn upgrade<'a>(&self, user: &'a User) -> Result<UserCredentialKey<'a>, CredentialError> {
        (*user.id() == self.id)
            .then_some(UserCredentialKey(user, CredentialKey(self.key)))
            .ok_or(CredentialError::Unauthorized)
    }
}

pub struct UserCredentialKey<'a>(&'a User, CredentialKey);

impl<'a> UserCredentialKey<'a> {
    pub fn claims(&self) -> UserCredentialClaims {
        UserCredentialClaims {
            id: *self.0.id(),
            key: self.1.0,
        }
    }

    fn aes(&self) -> Aes256Gcm { Aes256Gcm::new(self.1.0.as_generic()) }

    fn payload<'b, M: AsRef<[u8]>>(&self, msg: &'b M) -> Payload<'b, 'a> {
        Payload {
            msg: msg.as_ref(),
            aad: self.0.id().as_bytes(),
        }
    }
}

#[derive(Queryable, Insertable)]
#[diesel(check_for_backend(Pg))]
pub struct Credential {
    id: Uuid,
    name: String,
    owner: Uuid,
    nonce: Vec<u8>,
    creds: Vec<u8>,
}

impl Credential {
    pub async fn create<P: Into<payload::CredentialType>>(
        db: &mut Connection,
        key: &UserCredentialKey<'_>,
        payload: Named<P>,
    ) -> Result<Self, CredentialError> {
        let mut nonce = [0_u8; 12];
        rng().fill_bytes(&mut nonce);

        let Named { name, payload } = payload;
        let plaintext = ron::to_string(&payload.into()).map_err(|e| CredentialError::Internal)?;
        let ciphertext = key
            .aes()
            .encrypt(nonce.as_generic(), key.payload(&plaintext))
            .map_err(|e| CredentialError::Internal)?;

        let creds = Self {
            id: Uuid::new_v4(),
            name,
            owner: *key.0.id(),
            nonce: nonce.to_vec(),
            creds: ciphertext,
        };

        (&creds)
            .insert_into(credentials::table)
            .execute(db)
            .await
            .map_err(|e| CredentialError::Internal)?;

        Ok(creds)
    }

    pub fn decrypt<P: TryFrom<payload::CredentialType>>(
        &self,
        key: &UserCredentialKey,
    ) -> Result<P, CredentialError> {
        let plaintext = key
            .aes()
            .decrypt(
                self.nonce
                    .try_as_generic::<12>()
                    .map_err(|e| CredentialError::Internal)?,
                key.payload(&self.creds),
            )
            .map_err(|e| CredentialError::Unauthorized)?;

        let plaintext = std::str::from_utf8(&plaintext).map_err(|e| CredentialError::Internal)?;
        ron::from_str::<payload::CredentialType>(plaintext)
            .map_err(|e| CredentialError::Internal)?
            .try_into()
            .map_err(|e| CredentialError::Internal)
    }
}
