use diesel::{
    backend::Backend, deserialize, expression::AsExpression,
    query_builder::bind_collector::RawBytesBindCollector, serialize, sql_types::Text,
};
use rand::RngCore;

use super::user::{rng, Password};
use crate::prelude::*;

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
    // TODO: size this correctly!!
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
    pub unsafe fn derive_key(
        &self,
        params: &CredentialKeyParams,
        password: &Password,
    ) -> Result<CredentialKey, CredentialError> {
        derive(&self.0, params, password.as_bytes()).map(CredentialKey)
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

impl CredentialKey {
    #[inline]
    pub unsafe fn into_inner(self) -> [u8; KEY_SIZE] { self.0 }
}

// TODO: test
// TODO: make all my usages of argon2 consistent
// TODO: should LEN be a const?
fn derive<'a, const LEN: usize>(
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
