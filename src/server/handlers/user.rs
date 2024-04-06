use askama::Template;
use const_format::concatcp;
use poem::{get, handler, i18n::Locale, web::Redirect, IntoEndpoint, Route};

use super::{Templated, Trans};
use crate::prelude::*;

pub fn route() -> impl IntoEndpoint {
    Route::new()
        .at(INDEX_ROUTE, get(index))
        .at(FEEDS_ROUTE, get(feeds))
}

pub const INDEX_ROUTE: &str = "/user";

#[handler]
pub fn index() -> Redirect { Redirect::permanent(FEEDS_ROUTE) }

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
