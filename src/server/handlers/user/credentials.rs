use crate::{
    agent::AgentManager,
    db::{
        creds::{AtProtoCredentialForm, Credential, CredentialView},
        user::User,
    },
    server::{handlers::prelude::*, session::Session},
};

pub fn route() -> impl IntoEndpoint {
    use routes::user::credentials as routes;

    Route::new().at(routes::INDEX, get(index)).at(
        routes::ADD_ATPROTO,
        get(get_add_atproto).post(post_add_atproto),
    )
}

#[derive(Template)]
#[template(path = "user/credentials.html")]
pub struct IndexTemplate {
    l: Locale,
    creds: Vec<CredentialView>,
}

// TODO: add error handlers or something to make usage of ? nicer

pub async fn load_creds(session: Data<&Session>, db: Data<&Db>) -> Result<Vec<CredentialView>> {
    let mut db = db.get().await?;
    let user = User::from_id(&mut db, session.id())
        .await?
        .context("Invalid user")?;

    user.list_credentials(&mut db).await
}

#[handler]
pub async fn index(l: Locale, session: Data<&Session>, db: Data<&Db>) -> Templated<IndexTemplate> {
    let creds = load_creds(session, db).await.unwrap_or_else(|e| Vec::new());

    IndexTemplate { l, creds }.into()
}

struct AddAtProto;

#[derive(Template)]
#[template(path = "user/credentials/add-atproto.html")]
struct AddAtProtoTemplate {
    l: Locale,
    csrf: String,
    error: Option<String>,
}

struct_from_request! {
    struct AddAtProtoGet<'a> {
        csrf: &'a CsrfToken,
    }

    struct AddAtProtoPost<'a> {
        form: poem::Result<Form<AtProtoCredentialForm>>,
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

    const SUCCESS_ROUTE: &'static str = routes::user::credentials::INDEX;

    fn render(
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
            session,
            db,
            agents,
        }: Self::PostData<'_>,
    ) -> Result<(), Self::PostError> {
        create_atproto_cred(form, session, db, agents)
            .await
            .map_err(|e| ())
    }

    fn handle_error(error: Self::PostError) -> (StatusCode, &'static str) {
        (StatusCode::BAD_REQUEST, "add-credential-error-invalid")
    }
}

#[handler]
fn get_add_atproto(locale: Locale, data: AddAtProtoGet) -> impl IntoResponse {
    form_get::<AddAtProto>(locale, data)
}

#[handler]
async fn post_add_atproto(
    locale: Locale,
    render: AddAtProtoGet<'_>,
    post: AddAtProtoPost<'_>,
) -> Response {
    form_post::<AddAtProto>(locale, render, post).await
}

async fn create_atproto_cred(
    form: poem::Result<Form<AtProtoCredentialForm>>,
    session: Data<&Session>,
    db: Data<&Db>,
    agents: Data<&AgentManager>,
) -> Result<()> {
    let Form(payload) = form.map_err(|e| anyhow!("{e}"))?;

    let mut db = db.get().await?;
    let user = User::from_id(&mut db, session.id())
        .await?
        .context("Invalid user")?;
    let key = session.upgrade(&user)?;

    let agent = payload
        .login(&agents)
        .await
        .context("Error verifying login")?;
    let cred = Credential::create(&mut db, &key, payload).await?;

    Ok(())
}
