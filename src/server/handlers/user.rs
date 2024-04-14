use crate::server::{handlers::prelude::*, session::SessionMiddleware};

mod credentials;

pub fn route() -> impl IntoEndpoint {
    use routes::user as routes;

    Route::new()
        .at(routes::INDEX, get(index))
        .at(routes::FEEDS, get(feeds))
        .nest_no_strip(routes::credentials::INDEX, credentials::route())
        .with(SessionMiddleware::new(|| unauthorized))
}

// TODO: add a post-login redirect
#[handler]
pub fn unauthorized() -> Redirect { Redirect::see_other(routes::LOGIN) }


#[handler]
pub fn index() -> Redirect { Redirect::permanent(routes::user::FEEDS) }


#[derive(Template)]
#[template(path = "user/feeds.html")]
pub struct FeedsTemplate {
    l: Locale,
}

#[handler]
pub fn feeds(l: Locale) -> Templated<FeedsTemplate> { FeedsTemplate { l }.into() }
