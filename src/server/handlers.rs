use askama::Template;
use poem::{
    error::NotFoundError,
    handler,
    http::{header, StatusCode},
    web::Redirect,
    IntoResponse, Response,
};

use crate::prelude::*;

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
    csrf: String,
    error: Option<String>,
}

pub const INDEX_ROUTE: &str = "/";

#[handler]
pub fn index() -> Redirect { Redirect::permanent(LOGIN_ROUTE) }

pub const LOGIN_ROUTE: &str = "/login";
fn render_login(error: Option<String>) -> Templated<LoginTemplate> {
    LoginTemplate {
        csrf: "TODO".into(),
        error,
    }
    .into()
}

#[handler]
#[inline]
pub fn get_login() -> Templated<LoginTemplate> { render_login(None) }

#[handler]
pub fn post_login() -> Response {
    let err = 'err: {
        break 'err Some("Incorrect username or password.".into());

        None
    };

    if let Some(err) = err {
        render_login(Some(err)).into_response()
    } else {
        todo!();
    }
}

pub async fn catch_not_found(NotFoundError: NotFoundError) -> impl IntoResponse {
    (StatusCode::NOT_FOUND, "oops")
}
