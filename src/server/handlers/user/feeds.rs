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
        .at(routes::ADD_CONFIRM, form(AddConfirm))
}

#[derive(Template)]
#[template(path = "user/feeds.html")]
pub struct IndexTemplate {
    l: Locale,
}

#[handler]
pub fn index(l: Locale) -> Templated<IndexTemplate> { IndexTemplate { l }.into() }

enum AddError {
    InvalidCredentials,
    Internal,
}

impl From<AddError> for FormError {
    fn from(value: AddError) -> Self {
        match value {
            AddError::InvalidCredentials => FormError::Rerender(
                StatusCode::BAD_REQUEST,
                "add-feed-error-invalid-credentials",
            ),
            AddError::Internal => {
                FormError::Rerender(StatusCode::INTERNAL_SERVER_ERROR, "error-internal")
            },
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
enum AddFeedState {
    AtProto {
        credentials: Uuid,
        server: Url,
        username: String,
    },
    Confirm {
        credentials: Uuid,
        ty: AddFeedType,
        preview: Vec<Post>,
    },
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
enum AddFeedType {
    AtProto(AddAtProtoType),
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, tag = "type", rename_all = "snake_case")]
enum AddAtProtoType {
    Home { algorithm: Option<String> },
    Gen { feed: String },
}

type Post = ();

impl CookieName for AddFeedState {
    const COOKIE_NAME: &'static str = "add-feed-state";
    const COOKIE_PATH: &'static str = routes::user::feeds::ADD;
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
    credentials: String,
}

struct_from_request! {
    struct AddGet<'a> {
        csrf: &'a CsrfToken,
        session: Data<&'a Session>,
        db: Data<&'a Db>,
    }

    struct AddPost<'a> {
        session: Data<&'a Session>,
        cookies: &'a CookieJar,
        db: Data<&'a Db>,
    }
}

impl FormHandler for Add {
    type Form = AddForm;
    type PostData<'a> = AddPost<'a>;
    type RenderData<'a> = AddGet<'a>;
    type Rendered = Templated<AddTemplate>;

    const BAD_REQUEST: &'static str = "add-feed-error-invalid-credentials";

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

    async fn post(
        AddForm { credentials }: Self::Form,
        AddPost {
            session,
            cookies,
            db,
        }: Self::PostData<'_>,
    ) -> Result<&'static str, FormError> {
        let mut db = db
            .get()
            .await
            .erase_err("Error connecting to database", AddError::Internal)?;
        let user = User::from_id(&mut db, session.id())
            .await
            .erase_err(
                "Error loading current user from database",
                AddError::Internal,
            )?
            .ok_or_log("Invalid user", AddError::Internal)?;
        let key = session
            .upgrade(&user)
            .erase_err("Error loading user credential key", AddError::Internal)?;

        let cred = Credential::from_view_id(&mut db, &credentials)
            .await
            .erase_err(
                "Error loading credentials from database",
                AddError::Internal,
            )?
            .ok_or_log("Invalid credentials", AddError::Internal)?;
        let decrypted = cred
            .decrypt::<CredentialPayload>(&key)
            .erase_err("Error decrypting credentials", AddError::Internal)?;

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

        state
            .set_private(cookies)
            .erase_err("Error updating form state", AddError::Internal)?;

        Ok(route)
    }
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
    #[serde(flatten)]
    ty: AddAtProtoType,
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
        session: Data<&'a Session>,
        cookies: &'a CookieJar,
        db: Data<&'a Db>,
        agents: Data<&'a AgentManager>,
    }
}

impl FormHandler for AddAtProto {
    type Form = AddAtProtoForm;
    type PostData<'a> = AddAtProtoPost<'a>;
    type RenderData<'a> = AddAtProtoGet<'a>;
    type Rendered = Response;

    // TODO
    const BAD_REQUEST: &'static str = "error-internal";

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

    async fn post(
        AddAtProtoForm { ty }: Self::Form,
        AddAtProtoPost {
            session,
            cookies,
            db,
            agents,
        }: Self::PostData<'_>,
    ) -> Result<&'static str, FormError> {
        let Ok(AddFeedState::AtProto { credentials, .. }) = AddFeedState::get_private(cookies)
        else {
            error!("Invalid form state");
            return Err(AddError::Internal.into());
        };

        let mut db = db
            .get()
            .await
            .erase_err("Error connecting to database", AddError::Internal)?;
        let user = User::from_id(&mut db, session.id())
            .await
            .erase_err(
                "Error loading current user from database",
                AddError::Internal,
            )?
            .ok_or_log("Invalid user", AddError::Internal)?;
        let key = session
            .upgrade(&user)
            .erase_err("Error loading user credential key", AddError::Internal)?;

        let cred = Credential::from_id(&mut db, &credentials)
            .await
            .erase_err(
                "Error loading credentials from database",
                AddError::Internal,
            )?
            .ok_or_log("Invalid credentials", AddError::Internal)?;
        let decrypted = cred
            .decrypt::<AtProtoCredential>(&key)
            .erase_err("Error decrypting credentials", AddError::Internal)?;

        let agent = decrypted
            .login(&agents)
            .await
            .erase_err("Error logging in agent", AddError::Internal)?;

        let () = agent
            .get_feed(ty.clone().into(), None, 5)
            .await
            .erase_err("Error loading feed", AddError::Internal)?;

        let preview = vec![];

        AddFeedState::Confirm {
            credentials,
            ty: AddFeedType::AtProto(ty),
            preview,
        }
        .set_private(cookies)
        .erase_err("Error updating form state", AddError::Internal)?;

        Ok(routes::user::feeds::ADD_CONFIRM)
    }
}

struct AddConfirm;

#[derive(Template)]
#[template(path = "user/feeds/add-confirm.html")]
struct AddConfirmTemplate {
    l: Locale,
    preview: Vec<()>,
    csrf: String,
    error: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AddConfirmForm {
    name: String,
}

struct_from_request! {
    struct AddConfirmGet<'a> {
        csrf: &'a CsrfToken,
        cookies: &'a CookieJar,
    }

    struct AddConfirmPost<'a> {
        cookies: &'a CookieJar,
        db: Data<&'a Db>,
    }
}

impl FormHandler for AddConfirm {
    type Form = AddConfirmForm;
    type PostData<'a> = AddConfirmPost<'a>;
    type RenderData<'a> = AddConfirmGet<'a>;
    type Rendered = Response;

    // TODO
    const BAD_REQUEST: &'static str = "error-internal";

    async fn render(
        l: Locale,
        AddConfirmGet { csrf, cookies }: Self::RenderData<'_>,
        error: Option<String>,
    ) -> Self::Rendered {
        let Ok(AddFeedState::Confirm {
            credentials,
            ty,
            preview,
        }) = AddFeedState::get_private(cookies)
        else {
            return Redirect::see_other(routes::user::feeds::ADD).into_response();
        };

        AddConfirmTemplate {
            l,
            preview,
            csrf: csrf.0.clone(),
            error,
        }
        .render_response()
    }

    async fn post(
        AddConfirmForm { name }: Self::Form,
        AddConfirmPost { cookies, db }: Self::PostData<'_>,
    ) -> Result<&'static str, FormError> {
        let Ok(AddFeedState::Confirm {
            credentials, ty, ..
        }) = AddFeedState::get_private(cookies)
        else {
            error!("Invalid form state");
            return Err(AddError::Internal.into());
        };

        let mut db = db
            .get()
            .await
            .erase_err("Error connecting to database", AddError::Internal)?;

        error!("Not yet implemented");

        AddFeedState::delete_private(cookies);

        Ok(routes::user::feeds::INDEX)
    }
}
