use askama::Template;
use poem::{
    error::NotFoundError,
    get, handler,
    http::{header, StatusCode},
    i18n::Locale,
    middleware::{CookieJarManager, Csrf},
    web::{cookie::CookieJar, CsrfToken, CsrfVerifier, Data, Form, Redirect},
    EndpointExt, IntoEndpoint, IntoResponse, Response, Route,
};

use super::{
    locale,
    session::{AuthError, AuthForm, Session, SessionManager},
};
use crate::{db::{creds::CredentialManager, Db}, prelude::*};

mod user;

pub fn route() -> impl IntoEndpoint {
    // NOTE: .nest() and .nest_no_strip() are literally backwards from what the
    //       docs indicate their behavior should be.  whyyyy,,
    Route::new()
        .at(INDEX_ROUTE, get(index))
        .at(
            LOGIN_ROUTE,
            get(get_login).post(post_login).with(Csrf::new()),
        )
        .nest_no_strip(user::INDEX_ROUTE, user::route())
        .catch_error(catch_not_found)
        .data(locale::resources())
        .with(CookieJarManager::new())
}

trait Trans {
    fn t(&self, key: &str) -> String;
}

impl<T: Borrow<Locale>> Trans for T {
    fn t(&self, key: &str) -> String {
        let locale: &Locale = self.borrow();
        locale.text(key).unwrap_or_else(|err| {
            if cfg!(debug_assertions) {
                warn!(key, %err, "Localization error");
            }
            key.into()
        })
    }
}

#[repr(transparent)]
pub struct Templated<T>(T);

impl<T: Template + Send> IntoResponse for Templated<T> {
    fn into_response(self) -> Response {
        match self.0.render() {
            Ok(body) => body
                .with_header(header::CONTENT_TYPE, T::MIME_TYPE)
                .into_response(),
            Err(e) => {
                error!(%e, "Error rendering template");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            },
        }
    }
}

impl<T> From<T> for Templated<T> {
    #[inline]
    fn from(value: T) -> Self { Self(value) }
}

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    locale: Locale,
    csrf: String,
    error: Option<String>,
}

// TODO: either derive this or change the templates to use locale.t()
impl Borrow<Locale> for LoginTemplate {
    fn borrow(&self) -> &Locale { &self.locale }
}

pub const INDEX_ROUTE: &str = "/";

#[handler]
pub fn index() -> Redirect { Redirect::permanent(LOGIN_ROUTE) }

pub const LOGIN_ROUTE: &str = "/login";

fn render_login(
    csrf: &CsrfToken,
    locale: Locale,
    error: Option<String>,
) -> Templated<LoginTemplate> {
    LoginTemplate {
        locale,
        csrf: csrf.0.clone(),
        error,
    }
    .into()
}

#[handler]
#[inline]
pub fn get_login(csrf: &CsrfToken, locale: Locale) -> Templated<LoginTemplate> {
    render_login(csrf, locale, None)
}

#[handler]
pub async fn post_login(
    retry_csrf: &CsrfToken,
    csrf_verify: &CsrfVerifier,
    locale: Locale,
    form: poem::Result<Form<AuthForm>>,
    sessions: Data<&SessionManager>,
    cookies: &CookieJar,
    creds: Data<&CredentialManager>,
    db: Data<&Db>,
) -> Response {
    match sessions.auth(form, csrf_verify, cookies, &creds, &db).await {
        Ok(Session) => Redirect::see_other(user::INDEX_ROUTE).into_response(),
        Err(e) => {
            let (status, msg) = match e {
                AuthError::BadRequest => (StatusCode::BAD_REQUEST, "login-error-invalid"),
                AuthError::InternalError => {
                    (StatusCode::INTERNAL_SERVER_ERROR, "login-error-internal")
                },
                AuthError::Unauthorized => (StatusCode::UNAUTHORIZED, "login-error-unauthorized"),
            };

            let msg = locale.t(msg);
            render_login(retry_csrf, locale, Some(msg))
                .with_status(status)
                .into_response()
        },
    }
}

pub async fn catch_not_found(NotFoundError: NotFoundError) -> impl IntoResponse {
    (StatusCode::NOT_FOUND, "Page not found")
}
