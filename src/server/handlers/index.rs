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
        .at(routes::LOGIN, get(get_login).post(post_login))
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
    }

    struct LoginPost<'a> {
        form: poem::Result<Form<AuthForm>>,
        cookies: &'a CookieJar,
        csrf_verify: &'a CsrfVerifier,
        sessions: Data<&'a SessionManager>,
        creds: Data<&'a CredentialManager>,
        db: Data<&'a Db>,
    }
}

impl FormHandler for Login {
    type PostData<'a> = LoginPost<'a>;
    type PostError = AuthError;
    type RenderData<'a> = LoginGet<'a>;
    type Rendered = Templated<LoginTemplate>;

    async fn render(
        l: Locale,
        LoginGet { csrf }: Self::RenderData<'_>,
        error: Option<String>,
    ) -> Self::Rendered {
        LoginTemplate {
            l,
            csrf: csrf.0.clone(),
            error,
        }
        .into()
    }

    async fn post(
        LoginPost {
            form,
            cookies,
            csrf_verify,
            sessions,
            creds,
            db,
        }: Self::PostData<'_>,
    ) -> Result<&'static str, Self::PostError> {
        sessions
            .auth(form, csrf_verify, cookies, &creds, &db)
            .await
            .map(|_| routes::user::INDEX)
    }

    fn handle_error(err: Self::PostError) -> FormError {
        match err {
            AuthError::BadRequest => FormError::Rerender(StatusCode::BAD_REQUEST, "login-error-invalid"),
            AuthError::InternalError => FormError::Rerender(StatusCode::INTERNAL_SERVER_ERROR, "error-internal"),
            AuthError::Unauthorized => FormError::Rerender(StatusCode::UNAUTHORIZED, "login-error-unauthorized"),
            AuthError::AlreadyLoggedIn => FormError::SeeOther(routes::user::INDEX),
        }
    }
}

#[handler]
pub async fn get_login(
    locale: Locale,
    data: LoginGet<'_>,
    sessions: Data<&SessionManager>,
    cookies: &CookieJar,
) -> Response {
    if sessions.get(cookies).is_some() {
        Redirect::see_other(routes::user::INDEX).into_response()
    } else {
        form_get::<Login>(locale, data).await.into_response()
    }
}

#[handler]
pub async fn post_login(locale: Locale, render: LoginGet<'_>, post: LoginPost<'_>) -> Response {
    form_post::<Login>(locale, render, post).await
}

#[handler]
pub fn post_logout(cookies: &CookieJar) -> impl IntoResponse {
    SessionManager::remove(cookies);
    Redirect::see_other(routes::INDEX)
}
