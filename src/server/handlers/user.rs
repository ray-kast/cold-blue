use crate::server::{handlers::prelude::*, session::SessionMiddleware};

mod credentials;
mod feeds;

pub fn route() -> impl IntoEndpoint {
    use routes::user as routes;

    Route::new()
        .at(routes::INDEX, get(index))
        .nest_no_strip(routes::credentials::INDEX, credentials::route())
        .nest_no_strip(routes::feeds::INDEX, feeds::route())
        .with(SessionMiddleware::new(|| unauthorized))
}

// TODO: add a post-login redirect to return to the previous page
#[handler]
pub fn unauthorized() -> Redirect { Redirect::see_other(routes::LOGIN) }

#[handler]
pub fn index() -> Redirect { Redirect::permanent(routes::user::feeds::INDEX) }
