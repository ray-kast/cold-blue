use const_format::concatcp;
use poem::{
    get, handler, http::StatusCode, post, web::{Data, Form, Redirect}, IntoEndpoint, IntoResponse, Response, Route
};

use crate::{
    agent::AgentManager, db::{creds::{AtProtoCredential, AtProtoCredentialForm, Credential}, user::User, Db}, prelude::*, server::session::Session
};

pub fn route() -> impl IntoEndpoint {
    Route::new()
        .at(super::CREDENTIALS_ROUTE, get(super::get_credentials))
        .at(ATPROTO_ROUTE, post(post_atproto))
}

const INDEX_ROUTE: &str = super::CREDENTIALS_ROUTE;

pub const ATPROTO_ROUTE: &str = concatcp!(INDEX_ROUTE, "/atproto");

// TODO: the return type here should not be Result
#[handler]
async fn post_atproto(
    form: poem::Result<Form<AtProtoCredentialForm>>,
    session: Data<&Session>,
    db: Data<&Db>,
    agents: Data<&AgentManager>,
) -> Response {
    create_atproto_cred(form, session, db, agents)
        .await
        .unwrap_or_else(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response())
}

async fn create_atproto_cred(
    form: poem::Result<Form<AtProtoCredentialForm>>,
    session: Data<&Session>,
    db: Data<&Db>,
    agents: Data<&AgentManager>,
) -> Result<Response> {
    let Form(payload) = form.map_err(|e| anyhow!("{e}"))?;

    let mut db = db.get().await?;
    let user = User::from_id(&mut db, session.id()).await?.context("Invalid user")?;
    let key = session.upgrade(&user)?;

    let agent = payload.login(&agents).await.context("Error verifying login")?;
    let cred = Credential::create(&mut db, &key, payload).await?;

    Ok(Redirect::see_other(INDEX_ROUTE).into_response())
}
