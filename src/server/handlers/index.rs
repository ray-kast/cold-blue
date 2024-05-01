use super::user;
use crate::server::{
    handlers::prelude::*,
    session::{AuthError, AuthForm},
};

pub fn route() -> impl IntoEndpoint {
    // NOTE: .nest() and .nest_no_strip() are literally backwards from what the
    //       docs indicate their behavior should be.  whyyyy,,
    Route::new()
        .at(routes::INDEX, get(index))
        .at(routes::LOGIN, form(Login))
        .at(routes::LOGOUT, post(post_logout))
        .nest_no_strip(routes::user::INDEX, user::route())
}

#[handler]
pub fn index() -> Redirect { Redirect::permanent(routes::LOGIN) }

struct Login;

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    l: Locale,
    csrf: String,
    error: Option<String>,
}

struct_from_request! {
    struct LoginGet<'a> {
        csrf: &'a CsrfToken,
        cookies: &'a CookieJar,
        sessions: Data<&'a SessionManager>,
    }

    struct LoginPost<'a> {
        cookies: &'a CookieJar,
        sessions: Data<&'a SessionManager>,
        creds: Data<&'a CredentialManager>,
        db: Data<&'a Db>,
    }
}

impl FormHandler for Login {
    type Form = AuthForm;
    type PostData<'a> = LoginPost<'a>;
    type RenderData<'a> = LoginGet<'a>;
    type Rendered = Response;

    const BAD_REQUEST: &'static str = "login-error-invalid";

    async fn render(
        l: Locale,
        LoginGet {
            csrf,
            cookies,
            sessions,
        }: Self::RenderData<'_>,
        error: Option<String>,
    ) -> Self::Rendered {
        if sessions.get(cookies).is_some() {
            return Redirect::see_other(routes::user::INDEX).into_response();
        }

        LoginTemplate {
            l,
            csrf: csrf.0.clone(),
            error,
        }
        .render_response()
    }

    async fn post(
        form: Self::Form,
        LoginPost {
            cookies,
            sessions,
            creds,
            db,
        }: Self::PostData<'_>,
    ) -> Result<&'static str, FormError> {
        sessions
            .auth(form, cookies, &creds, &db)
            .await
            .map(|_| routes::user::INDEX)
            .map_err(login_error)
    }
}

#[allow(clippy::needless_pass_by_value)]
fn login_error(err: AuthError) -> FormError {
    match err {
        AuthError::BadRequest => {
            FormError::Rerender(StatusCode::BAD_REQUEST, "login-error-invalid")
        },
        AuthError::InternalError => {
            FormError::Rerender(StatusCode::INTERNAL_SERVER_ERROR, "error-internal")
        },
        AuthError::Unauthorized => {
            FormError::Rerender(StatusCode::UNAUTHORIZED, "login-error-unauthorized")
        },
        AuthError::AlreadyLoggedIn => FormError::SeeOther(routes::user::INDEX),
    }
}

#[handler]
pub fn post_logout(cookies: &CookieJar) -> impl IntoResponse {
    SessionManager::remove(cookies);
    Redirect::see_other(routes::INDEX)
}
