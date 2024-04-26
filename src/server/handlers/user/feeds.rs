use crate::{
    agent::AgentManager,
    db::{
        credentials::{Credential, CredentialPayload, CredentialView},
        user::User,
    },
    server::{handlers::prelude::*, session::Session},
};

pub fn route() -> impl IntoEndpoint {
    use routes::user::feeds as routes;

    Route::new()
        .at(routes::INDEX, get(index))
        .at(routes::ADD, get(get_add).post(post_add))
        .at(
            routes::ADD_ATPROTO,
            get(get_add_atproto).post(post_add_atproto),
        )
}

#[derive(Template)]
#[template(path = "user/feeds.html")]
pub struct IndexTemplate {
    l: Locale,
}

#[handler]
pub fn index(l: Locale) -> Templated<IndexTemplate> { IndexTemplate { l }.into() }

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
        csrf_verify: &'a CsrfVerifier,
        session: Data<&'a Session>,
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
            .unwrap_or_else(|e| Vec::new());

        AddTemplate {
            l,
            creds,
            csrf: csrf.0.clone(),
            error,
        }
        .into()
    }

    async fn post(
        AddPost { form, csrf_verify, session, db }: Self::PostData<'_>,
    ) -> Result<&'static str, Self::PostError> {
        decrypt_feed_cred(form, csrf_verify, session, db).await.map_err(|e| ())
    }

    fn handle_error(error: Self::PostError) -> (StatusCode, &'static str) {
        (StatusCode::BAD_REQUEST, "add-feed-error-invalid")
    }
}

async fn decrypt_feed_cred(
    form: poem::Result<Form<AddForm>>,
    csrf_verify: &CsrfVerifier,
    session: Data<&Session>,
    db: Data<&Db>,
) -> Result<&'static str> {
    let Form(AddForm { csrf, credentials }) = form.map_err(|e| anyhow!("{e}"))?;

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

    Ok(match *decrypted {
        CredentialPayload::AtProto(ref a) => routes::user::feeds::ADD_ATPROTO,
    })
}

#[handler]
async fn get_add(locale: Locale, data: AddGet<'_>) -> impl IntoResponse {
    form_get::<Add>(locale, data).await
}

#[handler]
async fn post_add(locale: Locale, render: AddGet<'_>, post: AddPost<'_>) -> Response {
    form_post::<Add>(locale, render, post).await
}

struct AddAtProto;

#[derive(Template)]
#[template(path = "user/feeds/add-atproto.html")]
struct AddAtProtoTemplate {
    l: Locale,
    csrf: String,
    error: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AddAtProtoForm {
    csrf: String,
}

struct_from_request! {
    struct AddAtProtoGet<'a> {
        csrf: &'a CsrfToken,
    }

    struct AddAtProtoPost<'a> {
        form: poem::Result<Form<AddAtProtoForm>>,
        csrf_verify: &'a CsrfVerifier,
        session: Data<&'a Session>,
        db: Data<&'a Db>,
        agents: Data<&'a AgentManager>,
    }
}

impl FormHandler for AddAtProto {
    type PostData<'a> = AddAtProtoPost<'a>;
    type PostError = ();
    type RenderData<'a> = AddAtProtoGet<'a>;
    type Rendered = Templated<AddAtProtoTemplate>;

    async fn render(
        l: Locale,
        AddAtProtoGet { csrf }: Self::RenderData<'_>,
        error: Option<String>,
    ) -> Self::Rendered {
        AddAtProtoTemplate {
            l,
            csrf: csrf.0.clone(),
            error,
        }
        .into()
    }

    async fn post(
        AddAtProtoPost {
            form,
            csrf_verify,
            session,
            db,
            agents,
        }: Self::PostData<'_>,
    ) -> Result<&'static str, Self::PostError> {
        create_atproto_feed(form, csrf_verify, session, db, agents)
            .await
            .map(|()| routes::user::feeds::INDEX)
            .map_err(|e| ())
    }

    fn handle_error(error: Self::PostError) -> (StatusCode, &'static str) {
        (StatusCode::BAD_REQUEST, "add-feed-error-invalid")
    }
}

#[handler]
async fn get_add_atproto(locale: Locale, data: AddAtProtoGet<'_>) -> impl IntoResponse {
    form_get::<AddAtProto>(locale, data).await
}

#[handler]
async fn post_add_atproto(
    locale: Locale,
    render: AddAtProtoGet<'_>,
    post: AddAtProtoPost<'_>,
) -> Response {
    form_post::<AddAtProto>(locale, render, post).await
}

async fn create_atproto_feed(
    form: poem::Result<Form<AddAtProtoForm>>,
    csrf_verify: &CsrfVerifier,
    session: Data<&Session>,
    db: Data<&Db>,
    agents: Data<&AgentManager>,
) -> Result<()> {
    let Form(AddAtProtoForm { csrf }) = form.map_err(|e| anyhow!("{e}"))?;

    ensure!(csrf_verify.is_valid(&csrf), "Invalid CSRF token");

    let mut db = db.get().await?;
    let user = User::from_id(&mut db, session.id())
        .await?
        .context("Invalid user")?;
    let key = session.upgrade(&user)?;

    Ok(())
}
