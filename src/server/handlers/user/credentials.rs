use crate::{
    agent::AgentManager,
    db::{
        credentials::{Credential, CredentialView, NamedAtProtoCredential},
        user::User,
    },
    server::{handlers::prelude::*, session::Session},
};

pub fn route() -> impl IntoEndpoint {
    use routes::user::credentials as routes;

    Route::new()
        .at(routes::INDEX, get(index))
        .at(routes::ADD_ATPROTO, form(AddAtProto))
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
    let creds = load_creds(session, db)
        .await
        .erase_err("Error listing user credentials", ())
        .unwrap_or_else(|()| Vec::new());

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

#[derive(serde::Deserialize)]
pub struct AddAtProtoForm {
    csrf: String,
    #[serde(flatten)]
    cred: NamedAtProtoCredential,
}

struct_from_request! {
    struct AddAtProtoGet<'a> {
        csrf: &'a CsrfToken,
    }

    struct AddAtProtoPost<'a> {
        form: poem::Result<Form<AddAtProtoForm>>,
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

    async fn post<'a>(
        csrf: &'a CsrfVerifier,
        data: Self::PostData<'a>,
    ) -> Result<&'static str, Self::PostError> {
        create_atproto_cred(csrf, data)
            .await
            .map(|()| routes::user::credentials::INDEX)
            .erase_err("Error adding ATProto credential", ())
    }

    fn handle_error(error: Self::PostError) -> FormError {
        FormError::Rerender(StatusCode::BAD_REQUEST, "add-credential-error-invalid")
    }
}

async fn create_atproto_cred(
    csrf_verify: &CsrfVerifier,
    AddAtProtoPost {
        form,
        session,
        db,
        agents,
    }: AddAtProtoPost<'_>,
) -> Result<()> {
    let Form(AddAtProtoForm { csrf, cred }) =
        form.anyhow_disp("Invalid ATProto credential form")?;

    ensure!(csrf_verify.is_valid(&csrf), "Invalid CSRF token");

    let mut db = db.get().await?;
    let user = User::from_id(&mut db, session.id())
        .await?
        .context("Invalid user")?;
    let key = session.upgrade(&user)?;

    let _agent = cred.login(&agents).await.context("Error verifying login")?;
    let _cred = Credential::create(&mut db, &key, cred).await?;

    Ok(())
}
