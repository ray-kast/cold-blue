use atrium_api::{
    agent::{store::MemorySessionStore, AtpAgent},
    app::bsky::feed::get_timeline,
};
use atrium_xrpc_client::reqwest::ReqwestClient;

use crate::prelude::*;

#[derive(Debug, clap::Args)]
#[allow(clippy::doc_markdown)]
pub struct AgentOpts {
    /// ATProto XRPC URL
    #[arg(long, env)]
    xrpc_uri: String,

    /// ATProto username
    #[arg(long, env)]
    atp_user: String,

    /// ATProto password
    #[arg(long, env)]
    atp_pass: String,
}

#[instrument(level = "error", name = "agent", skip(opts))]
pub async fn run(opts: AgentOpts) -> Result {
    let AgentOpts {
        xrpc_uri,
        atp_user,
        atp_pass,
    } = opts;

    let agent = AtpAgent::new(ReqwestClient::new(xrpc_uri), MemorySessionStore::default());
    agent
        .login(&atp_user, atp_pass)
        .await
        .with_context(|| format!("Error logging in as {atp_user:?}"))?;

    let feed = agent
        .api
        .app
        .bsky
        .feed
        .get_timeline(get_timeline::Parameters {
            algorithm: None,
            cursor: None,
            limit: Some(100.try_into().unwrap()),
        })
        .await
        .context("Error fetching home feed");

    let post = feed.as_ref().ok().and_then(|f| f.feed.first());

    let _ = post; // go away
    // debug!("{post:#?}");

    // let res = agent.
    Ok(())
}
