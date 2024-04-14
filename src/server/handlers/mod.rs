use askama::Template;
use poem::{
    error::NotFoundError,
    http::{header, StatusCode},
    i18n::Locale,
    middleware::{CookieJarManager, Csrf},
    EndpointExt, FromRequest, IntoEndpoint, IntoResponse, Response,
};

use crate::prelude::*;

mod index;
mod user;

mod routes {
    pub const INDEX: &str = "/";
    pub const LOGIN: &str = "/login";

    pub mod user {
        use const_format::concatcp;

        pub const INDEX: &str = "/user";
        pub const FEEDS: &str = concatcp!(INDEX, "/feeds");

        pub mod credentials {
            use const_format::concatcp;

            pub const INDEX: &str = concatcp!(super::INDEX, "/credentials");
            const ADD: &str = concatcp!(INDEX, "/add");
            pub const ADD_ATPROTO: &str = concatcp!(ADD, "/atproto");
        }
    }
}

mod prelude {
    pub use askama::Template;
    pub use poem::{
        get, handler,
        http::StatusCode,
        i18n::Locale,
        post,
        web::{cookie::CookieJar, CsrfToken, CsrfVerifier, Data, Form, Redirect},
        EndpointExt, IntoEndpoint, IntoResponse, Response, Route,
    };

    pub use super::{super::session::SessionManager, Templated};
    pub(super) use super::{form_get, form_post, routes, FormHandler, LocaleExt};
    pub use crate::{
        db::{creds::CredentialManager, Db},
        prelude::*,
        struct_from_request,
    };
}

trait LocaleExt {
    fn t(&self, key: &str) -> String;
}

impl LocaleExt for Locale {
    fn t(&self, key: &str) -> String {
        self.text(key).unwrap_or_else(|err| {
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

#[macro_export]
macro_rules! struct_from_request {
    {
        struct $name:ident$(<$($lt:lifetime),*>)? {
            $($field:ident: $field_ty:ty,)*
        }

        $($($tt:tt)+)?
    } => {
        struct $name$(<$($lt),*>)? {
            $($field: $field_ty,)*
        }

        impl<'a> poem::FromRequest<'a> for $name$(<$($lt),*>)? {
            async fn from_request(
                req: &'a poem::Request,
                body: &mut poem::RequestBody
            ) -> poem::Result<Self> {
                $(let $field = <$field_ty as poem::FromRequest>::from_request(req, body).await?;)*

                Ok(Self { $($field,)* })
            }
        }

        $(struct_from_request!($($tt)+);)?
    };
}

trait FormHandler {
    const SUCCESS_ROUTE: &'static str;

    type RenderData<'a>: FromRequest<'a> + Send;
    type Rendered: IntoResponse;

    type PostData<'a>: FromRequest<'a> + Send;
    type PostError;

    fn render(locale: Locale, data: Self::RenderData<'_>, error: Option<String>) -> Self::Rendered;

    fn post(data: Self::PostData<'_>) -> impl Future<Output = Result<(), Self::PostError>> + Send;

    fn handle_error(error: Self::PostError) -> (StatusCode, &'static str);
}

#[inline]
fn form_get<T: FormHandler + 'static>(locale: Locale, data: T::RenderData<'_>) -> T::Rendered {
    T::render(locale, data, None)
}

#[inline]
fn form_post<'a, T: FormHandler + 'static>(
    locale: Locale,
    render: T::RenderData<'a>,
    data: T::PostData<'a>,
) -> impl Future<Output = Response> + Send + 'a {
    T::post(data).map(|r| match r {
        Ok(()) => poem::web::Redirect::see_other(T::SUCCESS_ROUTE).into_response(),
        Err(e) => {
            let (status, msg) = T::handle_error(e);
            let msg = locale.t(msg);
            T::render(locale, render, Some(msg))
                .with_status(status)
                .into_response()
        },
    })
}

// TODO: make my usage of middleware & data type names consistent with poem's?
#[inline]
pub fn route() -> impl poem::IntoEndpoint {
    index::route()
        .into_endpoint()
        .catch_error(catch_not_found)
        .data(super::locale::resources())
        .with(CookieJarManager::new())
        .with(Csrf::new())
}

pub async fn catch_not_found(NotFoundError: NotFoundError) -> impl IntoResponse {
    (StatusCode::NOT_FOUND, "Page not found")
}