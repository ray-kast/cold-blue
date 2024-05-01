use poem::web::cookie::{Cookie, CookieJar, PrivateCookieJar, SameSite};
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Cookie not found: {0:?}")]
    Missing(&'static str),
    #[error("Serialization error")]
    Ser(#[from] ron::Error),
    #[error("Deserialization error")]
    De(#[from] ron::de::SpannedError),
}

pub trait CookieName {
    const COOKIE_NAME: &'static str;
    const COOKIE_PATH: &'static str;

    const REQUIRE_PRIVATE: bool = true;

    fn private_jar(cookies: &CookieJar) -> PrivateCookieJar<'_> { cookies.private() }

    fn build_cookie(cookie: &mut Cookie) {
        cookie.set_secure(true);
        cookie.set_http_only(true);
        cookie.set_same_site(SameSite::Strict);
    }
}

fn decode_cookie<T: CookieName + for<'de> Deserialize<'de>>(
    cookie: Option<Cookie>,
) -> Result<T, Error> {
    ron::from_str(cookie.ok_or(Error::Missing(T::COOKIE_NAME))?.value_str()).map_err(Into::into)
}

fn encode_cookie<T: CookieName + Serialize>(val: &T) -> Result<Cookie, Error> {
    let mut cookie = Cookie::new_with_str(T::COOKIE_NAME, ron::to_string(val)?);
    cookie.set_path(T::COOKIE_PATH);
    T::build_cookie(&mut cookie);
    Ok(cookie)
}

fn public_jar<T: CookieName>(cookies: &CookieJar) -> &CookieJar {
    assert!(
        !T::REQUIRE_PRIVATE,
        "Attempted to get non-private cookie with REQUIRE_PRIVATE set",
    );
    cookies
}

pub trait CookieExt: CookieName + Serialize + for<'de> Deserialize<'de> {
    fn get_private(cookies: &CookieJar) -> Result<Self, Error> {
        decode_cookie(Self::private_jar(cookies).get(Self::COOKIE_NAME))
    }

    fn set_private(&self, cookies: &CookieJar) -> Result<(), Error> {
        encode_cookie(self).map(|c| Self::private_jar(cookies).add(c))
    }

    fn delete_private(cookies: &CookieJar) { Self::private_jar(cookies).remove(Self::COOKIE_NAME); }

    fn get_cookie(cookies: &CookieJar) -> Result<Self, Error> {
        decode_cookie(public_jar::<Self>(cookies).get(Self::COOKIE_NAME))
    }

    fn set_cookie(&self, cookies: &CookieJar) -> Result<(), Error> {
        encode_cookie(self).map(|c| public_jar::<Self>(cookies).add(c))
    }

    fn delete_cookie(cookies: &CookieJar) { public_jar::<Self>(cookies).remove(Self::COOKIE_NAME); }
}

impl<T: CookieName + Serialize + for<'de> Deserialize<'de>> CookieExt for T {}
