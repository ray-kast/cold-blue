use uuid::Uuid;

use crate::{
    agent::{AgentManager, Feed, FeedGen, HomeFeed},
    db::{
        credentials::{AtProtoCredential, Credential, CredentialPayload, CredentialView},
        user::User,
    },
    server::{handlers::prelude::*, session::Session},
};

pub fn route() -> impl IntoEndpoint {
    use routes::user::feeds as routes;

    Route::new()
        .at(routes::INDEX, get(index))
        .at(routes::ADD, form(Add))
        .at(routes::ADD_ATPROTO, form(AddAtProto))
}

#[derive(Template)]
#[template(path = "user/feeds.html")]
pub struct IndexTemplate {
    l: Locale,
}

#[handler]
pub fn index(l: Locale) -> Templated<IndexTemplate> { IndexTemplate { l }.into() }

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
enum AddFeedState {
    AtProto {
        credentials: Uuid,
        server: Url,
        username: String,
    },
}

impl CookieName for AddFeedState {
    const COOKIE_NAME: &'static str = "add-feed-state";
}

struct Add;

#[derive(Template)]
#[template(path = "user/feeds/add.html")]
struct AddTemplate {
    l: Locale,
    creds: Vec<CredentialView>,
    csrf: String,
    error: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AddForm {
    csrf: String,
    credentials: String,
}

struct_from_request! {
    struct AddGet<'a> {
        csrf: &'a CsrfToken,
        session: Data<&'a Session>,
        db: Data<&'a Db>,
    }

    struct AddPost<'a> {
        form: poem::Result<Form<AddForm>>,
        session: Data<&'a Session>,
        cookies: &'a CookieJar,
        db: Data<&'a Db>,
    }
}

impl FormHandler for Add {
    type PostData<'a> = AddPost<'a>;
    type PostError = ();
    type RenderData<'a> = AddGet<'a>;
    type Rendered = Templated<AddTemplate>;

    async fn render(
        l: Locale,
        AddGet { csrf, session, db }: Self::RenderData<'_>,
        error: Option<String>,
    ) -> Self::Rendered {
        let creds = super::credentials::load_creds(session, db)
            .await
            .erase_err("Error listing user credentials", ())
            .unwrap_or_else(|()| Vec::new());

        AddTemplate {
            l,
            creds,
            csrf: csrf.0.clone(),
            error,
        }
        .into()
    }

    async fn post<'a>(
        csrf: &'a CsrfVerifier,
        data: Self::PostData<'a>,
    ) -> Result<&'static str, Self::PostError> {
        decrypt_feed_cred(csrf, data)
            .await
            .erase_err("Error decrypting feed credentials", ())
    }

    fn handle_error(error: Self::PostError) -> FormError {
        FormError::Rerender(
            StatusCode::BAD_REQUEST,
            "add-feed-error-invalid-credentials",
        )
    }
}

async fn decrypt_feed_cred(
    csrf_verify: &CsrfVerifier,
    AddPost {
        form,
        session,
        cookies,
        db,
    }: AddPost<'_>,
) -> Result<&'static str> {
    let Form(AddForm { csrf, credentials }) = form.anyhow_disp("Invalid feed credentials form")?;

    ensure!(csrf_verify.is_valid(&csrf), "Invalid CSRF token");

    let mut db = db.get().await?;
    let user = User::from_id(&mut db, session.id())
        .await?
        .context("Invalid user")?;
    let key = session.upgrade(&user)?;

    let cred = Credential::from_view_id(&mut db, &credentials)
        .await?
        .context("Invalid credentials")?;
    let decrypted = cred.decrypt::<CredentialPayload>(&key)?;

    let state;
    let route = match *decrypted {
        CredentialPayload::AtProto(ref a) => {
            state = AddFeedState::AtProto {
                credentials: *cred.id(),
                server: a.server.clone(),
                username: a.username.clone(),
            };
            routes::user::feeds::ADD_ATPROTO
        },
    };

    state.set_private(cookies)?;

    Ok(route)
}

struct AddAtProto;

#[derive(Template)]
#[template(path = "user/feeds/add-atproto.html")]
struct AddAtProtoTemplate {
    l: Locale,
    server: Url,
    username: String,
    csrf: String,
    error: Option<String>,
}

#[derive(serde::Deserialize)]
struct AddAtProtoForm {
    csrf: String,
    name: String,
    #[serde(flatten)]
    ty: AddAtProtoType,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields, tag = "type", rename_all = "snake_case")]
enum AddAtProtoType {
    Home { algorithm: Option<String> },
    Gen { feed: String },
}

impl From<AddAtProtoType> for Feed {
    fn from(value: AddAtProtoType) -> Self {
        match value {
            AddAtProtoType::Home { algorithm } => Self::Home(HomeFeed { algorithm }),
            AddAtProtoType::Gen { feed } => Self::Gen(FeedGen { feed }),
        }
    }
}

struct_from_request! {
    struct AddAtProtoGet<'a> {
        csrf: &'a CsrfToken,
        cookies: &'a CookieJar,
    }

    struct AddAtProtoPost<'a> {
        form: poem::Result<Form<AddAtProtoForm>>,
        session: Data<&'a Session>,
        cookies: &'a CookieJar,
        db: Data<&'a Db>,
        agents: Data<&'a AgentManager>,
    }
}

impl FormHandler for AddAtProto {
    type PostData<'a> = AddAtProtoPost<'a>;
    type PostError = ();
    type RenderData<'a> = AddAtProtoGet<'a>;
    type Rendered = Response;

    async fn render(
        l: Locale,
        AddAtProtoGet { csrf, cookies }: Self::RenderData<'_>,
        error: Option<String>,
    ) -> Self::Rendered {
        let Ok(AddFeedState::AtProto {
            server, username, ..
        }) = AddFeedState::get_private(cookies)
        else {
            return Redirect::see_other(routes::user::feeds::ADD).into_response();
        };

        AddAtProtoTemplate {
            l,
            server,
            username,
            csrf: csrf.0.clone(),
            error,
        }
        .render_response()
    }

    async fn post<'a>(
        csrf: &'a CsrfVerifier,
        data: Self::PostData<'a>,
    ) -> Result<&'static str, Self::PostError> {
        create_atproto_feed(csrf, data)
            .await
            .map(|()| routes::user::feeds::INDEX)
            .erase_err("Error creating ATProto feed", ())
    }

    fn handle_error(error: Self::PostError) -> FormError {
        FormError::Rerender(StatusCode::BAD_REQUEST, "error-internal")
    }
}

async fn create_atproto_feed(
    csrf_verify: &CsrfVerifier,
    AddAtProtoPost {
        form,
        session,
        cookies,
        db,
        agents,
    }: AddAtProtoPost<'_>,
) -> Result<()> {
    let Form(AddAtProtoForm { csrf, name, ty }) = form.anyhow_disp("Invalid ATProto feed form")?;

    let Ok(AddFeedState::AtProto { credentials, .. }) = AddFeedState::get_private(cookies) else {
        todo!()
    };

    ensure!(csrf_verify.is_valid(&csrf), "Invalid CSRF token");

    let mut db = db.get().await?;
    let user = User::from_id(&mut db, session.id())
        .await?
        .context("Invalid user")?;
    let key = session.upgrade(&user)?;

    let cred = Credential::from_id(&mut db, &credentials)
        .await?
        .context("Invalid credentials")?;
    let decrypted = cred.decrypt::<AtProtoCredential>(&key)?;

    let agent = decrypted.login(&agents).await.context("Error logging in")?;

    let () = agent
        .get_feed(&ty.into())
        .await
        .context("Error loading feed")?;

    Ok(())
}
