use std::{path::Path, time::Duration};

use jsonwebtoken as jwt;
use jwt::EncodingKey;
use poem::web::{
    cookie::{Cookie, CookieJar, CookieKey, PrivateCookieJar, SameSite},
    CsrfVerifier, Form,
};
use uuid::Uuid;

use crate::{
    db::{
        creds::CredentialError,
        user::{Password, User, Username},
        Db,
    },
    prelude::*,
};

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Bad authentication request")]
    BadRequest,
    #[error("Internal server error during authentication request")]
    InternalError,
    #[error("Invalid credentials for session auth")]
    Unauthorized,
}

impl From<CredentialError> for AuthError {
    fn from(value: CredentialError) -> Self {
        match value {
            CredentialError::Internal => AuthError::InternalError,
            CredentialError::Unauthorized => AuthError::Unauthorized,
        }
    }
}

#[derive(serde::Deserialize)]
pub struct AuthForm {
    csrf: String,
    username: Username,
    password: Password,
    #[serde(default)]
    remember: String,
}

#[derive(Clone)]
#[repr(transparent)]
pub struct SessionManager(Arc<SessionManagerInternal>);

// TODO: zeroize
struct SessionManagerInternal {
    encoding_key: jwt::EncodingKey,
    cookie_key: CookieKey,
}

impl SessionManager {
    // TODO: zeroize
    pub fn new<P: AsRef<Path>>(key_file: P, cookie_key: &str) -> Result<Self> {
        let encoding_key = {
            let key_file = key_file.as_ref();
            let bytes = std::fs::read(key_file)
                .with_context(|| format!("Error reading key file {key_file:?}"))?;

            EncodingKey::from_ed_pem(&bytes).context("Error deriving JWT encoding key")?
        };

        let cookie_key = {
            use base64::prelude::*;

            let bytes = BASE64_STANDARD
                .decode(cookie_key)
                .context("Error decoding base64 session cookie key")?;

            CookieKey::try_from(&*bytes).context("Error deriving session cookie key")?
        };

        Ok(Self(
            SessionManagerInternal {
                encoding_key,
                cookie_key,
            }
            .into(),
        ))
    }

    fn cookie<F: FnOnce(&mut Cookie)>(expires: DateTime<Utc>, remember: bool, f: F) -> Cookie {
        // Discard expiry for non-private sessions to avoid bugs
        let expires = remember.then_some(expires);

        let mut cookie = Cookie::named("session");
        cookie.set_secure(true);
        cookie.set_http_only(true);
        cookie.set_same_site(SameSite::Strict);

        if let Some(expires) = expires {
            cookie.set_max_age((expires - Utc::now()).to_std().unwrap_or_else(|err| {
                warn!(%err, "Error calculating session cookie max age");
                Duration::from_secs(3600)
            }));
            cookie.set_expires(expires);
        }

        f(&mut cookie);

        cookie
    }

    fn private_jar<'a>(&'a self, cookies: &'a CookieJar) -> PrivateCookieJar {
        cookies.private_with_key(&self.0.cookie_key)
    }

    pub async fn auth(
        &self,
        form: poem::Result<Form<AuthForm>>,
        csrf_verify: &CsrfVerifier,
        cookies: &CookieJar,
        db: &Db,
    ) -> Result<Session, AuthError> {
        // TODO: make this more descriptive?
        let Form(AuthForm {
            csrf,
            username,
            password,
            remember,
        }) = form.map_err(|_e| AuthError::BadRequest)?;

        if !csrf_verify.is_valid(&csrf) {
            return Err(AuthError::BadRequest);
        }

        let remember = match &*remember {
            "" => false,
            "on" => true,
            _ => return Err(AuthError::BadRequest),
        };

        // TODO: replace the log-and-map-error pattern
        let user = User::from_username(
            &mut *db.get().await.map_err(|err| {
                error!(%err, "Database error during login");
                AuthError::InternalError
            })?,
            &username,
        )
        .await
        .map_err(|err| {
            error!(%err, "Error finding user to log in");
            AuthError::InternalError
        })
        .and_then(|u| u.ok_or(AuthError::Unauthorized))?;

        let cred_key = user.get_credential_key(&password)?;
        let expires = Utc::now() + chrono::Duration::days(if remember { 30 } else { 1 });

        // TODO: assert that we have valid credentials before returning
        let claims = Claims {
            id: *user.id(), // TODO
            key: unsafe { cred_key.into_inner().to_vec() },
            expires,
        };

        let token = jwt::encode(
            &jwt::Header::new(jwt::Algorithm::EdDSA),
            &claims,
            &self.0.encoding_key,
        )
        .map_err(|err| {
            warn!(%err, %username, "Error encoding JWT");
            AuthError::InternalError
        })?;

        self.private_jar(cookies)
            .add(Self::cookie(expires, remember, |c| c.set_value_str(&token)));

        Ok(Session)
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Claims {
    id: Uuid,
    // TODO: zeroize
    key: Vec<u8>,
    expires: DateTime<Utc>,
}

pub struct Session;
