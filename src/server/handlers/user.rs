use askama::Template;
use const_format::concatcp;
use poem::{
    get, handler,
    i18n::Locale,
    web::{CsrfToken, Redirect},
    EndpointExt, IntoEndpoint, Route,
};

use super::{Templated, Trans};
use crate::{prelude::*, server::session::SessionMiddleware};

mod credentials;

pub fn route() -> impl IntoEndpoint {
    Route::new()
        .at(INDEX_ROUTE, get(index))
        .at(FEEDS_ROUTE, get(feeds))
        .nest_no_strip(CREDENTIALS_ROUTE, credentials::route())
        .with(SessionMiddleware::new(|| unauthorized))
}

// TODO: add a post-login redirect
#[handler]
pub fn unauthorized() -> Redirect { Redirect::see_other(super::LOGIN_ROUTE) }

pub const INDEX_ROUTE: &str = "/user";

#[handler]
pub fn index() -> Redirect { Redirect::permanent(FEEDS_ROUTE) }

const CREDENTIALS_ROUTE: &str = concatcp!(INDEX_ROUTE, "/credentials");

#[derive(Template)]
#[template(path = "user/credentials.html")]
pub struct CredentialsTemplate {
    locale: Locale,
    csrf: String,
}

impl Borrow<Locale> for CredentialsTemplate {
    fn borrow(&self) -> &Locale { &self.locale }
}

#[handler]
pub fn get_credentials(locale: Locale, csrf: &CsrfToken) -> Templated<CredentialsTemplate> {
    CredentialsTemplate {
        locale,
        csrf: csrf.0.clone(),
    }
    .into()
}

const FEEDS_ROUTE: &str = concatcp!(INDEX_ROUTE, "/feeds");

#[derive(Template)]
#[template(path = "user/feeds.html")]
pub struct FeedsTemplate {
    locale: Locale,
}

impl Borrow<Locale> for FeedsTemplate {
    fn borrow(&self) -> &Locale { &self.locale }
}

#[handler]
pub fn feeds(locale: Locale) -> Templated<FeedsTemplate> { FeedsTemplate { locale }.into() }
