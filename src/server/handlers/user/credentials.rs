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

struct AddError;

impl From<AddError> for FormError {
    fn from(value: AddError) -> Self {
        FormError::Rerender(StatusCode::BAD_REQUEST, "add-credential-error-invalid")
    }
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
    #[serde(flatten)]
    cred: NamedAtProtoCredential,
}

struct_from_request! {
    struct AddAtProtoGet<'a> {
        csrf: &'a CsrfToken,
    }

    struct AddAtProtoPost<'a> {
        session: Data<&'a Session>,
        db: Data<&'a Db>,
        agents: Data<&'a AgentManager>,
    }
}

impl FormHandler for AddAtProto {
    type Form = AddAtProtoForm;
    type PostData<'a> = AddAtProtoPost<'a>;
    type RenderData<'a> = AddAtProtoGet<'a>;
    type Rendered = Templated<AddAtProtoTemplate>;

    const BAD_REQUEST: &'static str = "add-credential-error-invalid";

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
        AddAtProtoForm { cred }: Self::Form,
        AddAtProtoPost {
            session,
            db,
            agents,
        }: Self::PostData<'_>,
    ) -> Result<&'static str, FormError> {
        let mut db = db
            .get()
            .await
            .erase_err("Error connecting to database", AddError)?;
        let user = User::from_id(&mut db, session.id())
            .await
            .erase_err("Error loading current user from database", AddError)?
            .ok_or_log("Invalid user", AddError)?;
        let key = session
            .upgrade(&user)
            .erase_err("Error loading user credential key", AddError)?;

        let _agent = cred
            .login(&agents)
            .await
            .erase_err("Error verifying login", AddError)?;
        let _cred = Credential::create(&mut db, &key, cred)
            .await
            .erase_err("Error writing credential to database", AddError)?;

        Ok(routes::user::credentials::INDEX)
    }
}
