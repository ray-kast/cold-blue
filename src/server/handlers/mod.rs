use std::future;

use askama::Template;
use either::Either;
use poem::{
    error::NotFoundError,
    http::{header, StatusCode},
    i18n::Locale,
    middleware::{CookieJarManager, Csrf},
    web::cookie::CookieKey,
    EndpointExt, FromRequest, IntoEndpoint, IntoResponse, Response,
};

use crate::prelude::*;

mod index;
mod user;

mod routes {
    pub const INDEX: &str = "/";
    pub const LOGIN: &str = "/login";
    pub const LOGOUT: &str = "/logout";

    pub mod user {
        pub const INDEX: &str = "/user";

        pub mod credentials {
            use const_format::concatcp;

            pub const INDEX: &str = concatcp!(super::INDEX, "/credentials");
            const ADD: &str = concatcp!(INDEX, "/add");
            pub const ADD_ATPROTO: &str = concatcp!(ADD, "/atproto");
        }

        pub mod feeds {
            use const_format::concatcp;

            pub const INDEX: &str = concatcp!(super::INDEX, "/feeds");
            pub const ADD: &str = concatcp!(INDEX, "/add");
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

    pub use super::{
        super::{
            cookies::{CookieExt, CookieName},
            session::SessionManager,
        },
        TemplateExt, Templated,
    };
    pub(super) use super::{form_get, form_post, routes, FormError, FormHandler, LocaleExt};
    pub use crate::{
        db::{credentials::CredentialManager, Db},
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

pub trait TemplateExt: Template + Send + Sized {
    #[inline]
    fn templated(self) -> Templated<Self> { self.into() }

    fn render_response(self) -> Response { self.templated().into_response() }
}

impl<T: Template + Send + Sized> TemplateExt for T {}

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

enum FormError {
    /// Rerender the current page with an error message
    Rerender(StatusCode, &'static str),
    SeeOther(&'static str),
}

trait FormHandler: Send + 'static {
    type RenderData<'a>: FromRequest<'a> + Send;
    type Rendered: IntoResponse;

    type PostData<'a>: FromRequest<'a> + Send;
    type PostError: Send;

    fn render(
        locale: Locale,
        data: Self::RenderData<'_>,
        error: Option<String>,
    ) -> impl Future<Output = Self::Rendered> + Send + '_;

    /// Returns a redirect route on success
    fn post(
        data: Self::PostData<'_>,
    ) -> impl Future<Output = Result<&'static str, Self::PostError>> + Send + '_;

    fn handle_error(error: Self::PostError) -> FormError;
}

#[inline]
fn form_get<T: FormHandler>(
    locale: Locale,
    data: T::RenderData<'_>,
) -> impl Future<Output = T::Rendered> + '_ {
    T::render(locale, data, None)
}

// TODO: make this async once they fix the stupid lifetime bug
//       https://github.com/rust-lang/rust/issues/100013
#[inline]
fn form_post<'a, T: FormHandler>(
    locale: Locale,
    render: T::RenderData<'a>,
    data: T::PostData<'a>,
) -> impl Future<Output = Response> + Send + 'a {
    T::post(data)
        .map_ok(|r| poem::web::Redirect::see_other(r).into_response())
        .or_else(|e| match T::handle_error(e) {
            FormError::Rerender(s, m) => Either::Left({
                let m = locale.t(m);
                T::render(locale, render, Some(m))
                    .map(move |r| Ok(r.with_status(s).into_response()))
            }),
            FormError::SeeOther(r) => Either::Right(future::ready(Ok(
                poem::web::Redirect::see_other(r).into_response(),
            ))),
        })
        .unwrap_or_else(|e: Infallible| match e {})

    // async move {
    //     match T::post(data).await {
    //         Ok(()) => poem::web::Redirect::see_other(T::SUCCESS_ROUTE).into_response(),
    //         Err(e) => {
    //             let (status, msg) = T::handle_error(e);
    //             let msg = locale.t(msg);
    //             T::render(locale, render, Some(msg))
    //                 .await
    //                 .with_status(status)
    //                 .into_response()
    //         },
    //     }
    // }
}

// TODO: make my usage of middleware & data type names consistent with poem's?
#[inline]
pub fn route() -> impl poem::IntoEndpoint {
    index::route()
        .into_endpoint()
        .catch_error(catch_not_found)
        .data(super::locale::resources())
        .with(Csrf::new())
        .with(CookieJarManager::with_key(CookieKey::generate()))
}

pub async fn catch_not_found(NotFoundError: NotFoundError) -> impl IntoResponse {
    (StatusCode::NOT_FOUND, "Page not found")
}
