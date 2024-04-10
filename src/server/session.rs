use std::{ops::Deref, path::Path, time::Duration};

use jsonwebtoken as jwt;
use poem::{
    web::{
        cookie::{Cookie, CookieJar, CookieKey, PrivateCookieJar, SameSite},
        CsrfVerifier, Form,
    },
    Endpoint, IntoResponse, Middleware,
};

use crate::{
    db::{
        creds::{CredentialError, CredentialManager, UserCredentialClaims},
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
    #[error("User already logged in")]
    AlreadyLoggedIn,
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
#[allow(clippy::struct_field_names)]
struct SessionManagerInternal {
    encoding_key: jwt::EncodingKey,
    decoding_key: jwt::DecodingKey,
    cookie_key: CookieKey,
}

impl SessionManager {
    const COOKIE_NAME: &'static str = "session";

    // TODO: zeroize
    pub fn new<P: AsRef<Path>>(enc_key_file: P, dec_key_file: P, cookie_key: &str) -> Result<Self> {
        let encoding_key = {
            let key_file = enc_key_file.as_ref();
            let bytes = std::fs::read(key_file)
                .with_context(|| format!("Error reading key file {key_file:?}"))?;

            jwt::EncodingKey::from_ed_pem(&bytes).context("Error deriving JWT encoding key")?
        };

        let decoding_key = {
            let key_file = dec_key_file.as_ref();
            let bytes = std::fs::read(key_file)
                .with_context(|| format!("Error reading key file {key_file:?}"))?;

            jwt::DecodingKey::from_ed_pem(&bytes).context("Error deriving JWT decoding key")?
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
                decoding_key,
                cookie_key,
            }
            .into(),
        ))
    }

    fn cookie<F: FnOnce(&mut Cookie)>(expires: DateTime<Utc>, remember: bool, f: F) -> Cookie {
        // Discard expiry for non-private sessions to avoid bugs
        let expires = remember.then_some(expires);

        let mut cookie = Cookie::named(Self::COOKIE_NAME);
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

    pub fn get(&self, cookies: &CookieJar) -> Option<Session> {
        let cookie = self.private_jar(cookies).get(Self::COOKIE_NAME)?;

        let jwt = jwt::decode::<Claims>(
            cookie.value_str(),
            &self.0.decoding_key,
            &jwt::Validation::new(jwt::Algorithm::EdDSA),
        );

        if cfg!(debug_assertions) {
            if let Err(ref err) = jwt {
                warn!(%err, "Rejecting session cookie due to invalid JWT");
            }
        }

        let jwt = jwt.ok()?;

        // TODO: does jwt check this?
        let exp = jwt
            .claims
            .exp
            .try_into()
            .ok()
            .and_then(|e| DateTime::from_timestamp(e, 0))?;

        if exp <= Utc::now() {
            return None;
        }

        Some(Session(
            SessionInner {
                credential: jwt.claims.credential,
            }
            .into(),
        ))
    }

    pub async fn auth(
        &self,
        form: poem::Result<Form<AuthForm>>,
        csrf_verify: &CsrfVerifier,
        cookies: &CookieJar,
        creds: &CredentialManager,
        db: &Db,
    ) -> Result<Session, AuthError> {
        if self.get(cookies).is_some() {
            return Err(AuthError::AlreadyLoggedIn);
        }

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

        let cred_key = user.derive_credential_key(creds, &password)?;
        let expires = Utc::now() + chrono::Duration::days(if remember { 30 } else { 1 });

        // TODO: assert that we have valid credentials before returning
        let claims = Claims {
            credential: cred_key.claims(),
            exp: expires
                .timestamp()
                .try_into()
                .expect("Couldn't convert timestamp to unsigned - is the system time correct?"),
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

        Ok(Session(
            SessionInner {
                credential: claims.credential,
            }
            .into(),
        ))
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Claims {
    credential: UserCredentialClaims,
    exp: u64,
}

#[derive(Clone)]
pub struct Session(Arc<SessionInner>);

struct SessionInner {
    credential: UserCredentialClaims,
}

impl Deref for Session {
    type Target = UserCredentialClaims;

    fn deref(&self) -> &Self::Target { &self.0.credential }
}

pub struct SessionMiddleware<U> {
    unauth: U,
}

impl<U> SessionMiddleware<U> {
    #[inline]
    #[must_use]
    pub fn new(unauth: U) -> Self { Self { unauth } }
}

impl<E: Endpoint, U: Fn() -> V, V: Endpoint> Middleware<E> for SessionMiddleware<U> {
    type Output = SessionEndpoint<E, V>;

    fn transform(&self, ep: E) -> Self::Output {
        SessionEndpoint {
            ep,
            unauth: (self.unauth)(),
        }
    }
}

pub struct SessionEndpoint<E, U> {
    ep: E,
    unauth: U,
}

impl<E: Endpoint, U: Endpoint> Endpoint for SessionEndpoint<E, U> {
    type Output = SessionResponse<E::Output, U::Output>;

    async fn call(&self, mut req: poem::Request) -> poem::Result<Self::Output> {
        match req
            .extensions()
            .get::<SessionManager>()
            .expect("")
            .get(req.cookie())
        {
            Some(s) => {
                req.extensions_mut().insert(s);
                self.ep.call(req).await.map(SessionResponse::Inner)
            },
            None => self
                .unauth
                .call(req)
                .await
                .map(SessionResponse::Unauthorized),
        }
    }
}

pub enum SessionResponse<E, U> {
    Inner(E),
    Unauthorized(U),
}

impl<E: IntoResponse, U: IntoResponse> IntoResponse for SessionResponse<E, U> {
    #[inline]
    fn into_response(self) -> poem::Response {
        match self {
            SessionResponse::Inner(i) => i.into_response(),
            SessionResponse::Unauthorized(r) => r.into_response(),
        }
    }
}
