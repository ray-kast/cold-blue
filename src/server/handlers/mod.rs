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
    pub(super) use super::{form, form_get, form_post, routes, FormError, FormHandler, LocaleExt};
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
    fn post<'a>(
        csrf: &'a poem::web::CsrfVerifier,
        data: Self::PostData<'a>,
    ) -> impl Future<Output = Result<&'static str, Self::PostError>> + Send + 'a;

    fn handle_error(error: Self::PostError) -> FormError;
}

struct FormGet<'a, T: FormHandler> {
    pub locale: Locale,
    pub data: T::RenderData<'a>,
}

impl<'a, T: FormHandler> FormGet<'a, T> {
    pub fn handle(self) -> impl Future<Output = T::Rendered> + 'a {
        let Self { locale, data } = self;
        T::render(locale, data, None)
    }
}

impl<'a, T: FormHandler> poem::FromRequest<'a> for FormGet<'a, T> {
    // TODO: make this async once they fix the stupid lifetime bug
    //       https://github.com/rust-lang/rust/issues/100013
    fn from_request(
        req: &'a poem::Request,
        body: &mut poem::RequestBody,
    ) -> impl Future<Output = poem::Result<Self>> + Send {
        async move {
            let l = <Locale as poem::FromRequest>::from_request(req, body).await?;
            Ok((l, body))
        }
        .and_then(move |(locale, b)| {
            <T::RenderData<'a> as poem::FromRequest>::from_request(req, b)
                .map_ok(|data| Self { locale, data })
        })
    }
}

struct FormPost<'a, T: FormHandler> {
    pub locale: Locale,
    pub csrf: &'a poem::web::CsrfVerifier,
    pub render: T::RenderData<'a>,
    pub data: T::PostData<'a>,
}

impl<'a, T: FormHandler> poem::FromRequest<'a> for FormPost<'a, T> {
    // TODO: make this async once they fix the stupid lifetime bug
    //       https://github.com/rust-lang/rust/issues/100013
    fn from_request(
        req: &'a poem::Request,
        body: &mut poem::RequestBody,
    ) -> impl Future<Output = poem::Result<Self>> + Send {
        async move {
            let l = <Locale as poem::FromRequest>::from_request(req, body).await?;
            let c =
                <&poem::web::CsrfVerifier as poem::FromRequest>::from_request(req, body).await?;
            Ok((l, c, body))
        }
        .and_then(move |(locale, csrf, b)| {
            <T::RenderData<'a> as poem::FromRequest>::from_request_without_body(req).and_then(
                move |render| {
                    <T::PostData<'a> as poem::FromRequest>::from_request(req, b).map_ok(|data| {
                        Self {
                            locale,
                            csrf,
                            render,
                            data,
                        }
                    })
                },
            )
        })
    }
}

impl<'a, T: FormHandler> FormPost<'a, T> {
    // TODO: make this async once they fix the stupid lifetime bug
    //       https://github.com/rust-lang/rust/issues/100013
    pub fn handle(self) -> impl Future<Output = Response> + Send + 'a {
        let Self {
            locale,
            csrf,
            render,
            data,
        } = self;

        T::post(csrf, data)
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
}

struct FormGetHandler<T>(PhantomData<fn(&T)>);

impl<T: FormHandler + Send> poem::Endpoint for FormGetHandler<T> {
    type Output = T::Rendered;

    async fn call(&self, req: poem::Request) -> poem::Result<Self::Output> {
        let (req, mut body) = req.split();
        let get = <FormGet<T> as poem::FromRequest>::from_request(&req, &mut body).await?;
        Ok(get.handle().await)
    }
}

struct FormPostHandler<T>(PhantomData<fn(&T)>);

impl<T: FormHandler + Send> poem::Endpoint for FormPostHandler<T> {
    type Output = Response;

    async fn call(&self, req: poem::Request) -> poem::Result<Self::Output> {
        let (req, mut body) = req.split();
        let post = <FormPost<T> as poem::FromRequest>::from_request(&req, &mut body).await?;
        Ok(post.handle().await)
    }
}

#[inline]
fn form_get<T>(_: T) -> FormGetHandler<T> { FormGetHandler(PhantomData) }

#[inline]
fn form_post<T>(_: T) -> FormPostHandler<T> { FormPostHandler(PhantomData) }

#[inline]
fn form<T: FormHandler>(_: T) -> poem::RouteMethod {
    poem::get(FormGetHandler::<T>(PhantomData)).post(FormPostHandler::<T>(PhantomData))
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
