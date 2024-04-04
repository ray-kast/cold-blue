use askama::Template;
use poem::{
    error::NotFoundError,
    handler,
    http::{header, StatusCode},
    i18n::Locale,
    web::{CsrfToken, CsrfVerifier, Form, Redirect},
    IntoResponse, Response,
};

use crate::prelude::*;

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

#[derive(serde::Deserialize)]
pub struct LoginForm {
    csrf: String,
    username: String,
    password: String,
}

#[handler]
pub fn post_login(
    retry_csrf: &CsrfToken,
    csrf_verify: &CsrfVerifier,
    locale: Locale,
    Form(form): Form<LoginForm>,
) -> Response {
    let err = 'err: {
        let LoginForm {
            csrf,
            username,
            password,
        } = form;

        if !csrf_verify.is_valid(&csrf) || username != "admin" || password != "123" {
            break 'err Some((
                StatusCode::UNAUTHORIZED,
                locale.t("login-error-unauthorized"),
            ));
        }

        None
    };

    if let Some((status, err)) = err {
        render_login(retry_csrf, locale, Some(err))
            .with_status(status)
            .into_response()
    } else {
        Redirect::temporary(USER_HOME).into_response()
    }
}

const USER_HOME: &str = "/fuck";

pub async fn catch_not_found(NotFoundError: NotFoundError) -> impl IntoResponse {
    (StatusCode::NOT_FOUND, "Page not found")
}
