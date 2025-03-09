use std::time::Duration;

use atrium_api::{
    agent::{store::MemorySessionStore, AtpAgent},
    app::bsky::feed::{get_feed, get_timeline},
};
use atrium_xrpc_client::reqwest::ReqwestClient;
use dashmap::DashMap;
use dispose::AbortCanary;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha512;
use tokio::{
    sync::oneshot,
    time::{interval_at, Instant},
};

use crate::{db::{feed::{AtProtoFeed, FeedParams}, user::rng}, prelude::*};

#[derive(Debug, Clone, Copy, clap::Args)]
#[allow(clippy::doc_markdown)]
pub struct AgentOpts {
    /// Timeout for cleaning up ATProtocol agents
    #[arg(long, env, default_value_t = 120)]
    atp_cleanup_timeout: u64,

    /// Interval on which ATProtocol agents are checked for cleanup
    #[arg(long, env, default_value_t = 120)]
    atp_cleanup_interval: u64,
}

#[derive(Clone)]
#[repr(transparent)]
pub struct AgentManager(Arc<AgentManagerInner>);

const AGENT_KEY_SIE: usize = 64;
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct AgentKey([u8; AGENT_KEY_SIE]);

struct AgentManagerInner {
    hasher_key: [u8; 128],
    // TODO: don't do it like this
    // TODO: expire agents after a timeout
    agents: DashMap<AgentKey, Arc<AgentInner>>,
    stop_tx: oneshot::Sender<()>,
}

impl AgentManager {
    #[must_use]
    pub fn new(opts: AgentOpts) -> Self {
        let AgentOpts {
            atp_cleanup_timeout,
            atp_cleanup_interval,
        } = opts;
        let atp_cleanup_timeout = Duration::from_secs(atp_cleanup_timeout);
        let atp_cleanup_interval = Duration::from_secs(atp_cleanup_interval);

        let mut hasher_key = [0_u8; 128];
        rng().fill_bytes(&mut hasher_key);

        let (stop_tx, mut rx) = oneshot::channel();

        let inner = Arc::new(AgentManagerInner {
            hasher_key,
            agents: DashMap::new(),
            stop_tx,
        });

        let this = Arc::clone(&inner);
        tokio::spawn(
            async move {
                let canary = AbortCanary::new();

                let mut int =
                    interval_at(Instant::now() + atp_cleanup_interval, atp_cleanup_interval);
                loop {
                    let evt = tokio::select! {
                        i = int.tick() => Ok(Some(i)),
                        r = &mut rx => r.map(|()| None),
                    };

                    match evt {
                        Ok(Some(now)) => {
                            trace!("Starting ATProto agent cleanup...");

                            let dropped_at = now - atp_cleanup_timeout;

                            let mut dropped = 0_u32;
                            this.agents.retain(|_, v| {
                                let dead = v.dropped_at.lock().is_some_and(|d| d <= dropped_at);
                                dropped += u32::from(dead);
                                !dead
                            });

                            if dropped > 0 {
                                debug!(dropped, "Finished ATProto agent cleanup");
                            } else {
                                trace!("No agents were cleaned up");
                            }
                        },
                        Ok(None) | Err(_) => {
                            debug!("Stopping ATProto agent manager...");
                            break;
                        },
                    }
                }

                AbortCanary::release(canary);
            }
            .instrument(error_span!("atp_cleanup")),
        );

        Self(inner)
    }

    fn hash(&self, xrpc_uri: &Url, atp_user: &str, atp_pass: &str) -> Result<AgentKey> {
        Ok(AgentKey(
            Hmac::<Sha512>::new(self.0.hasher_key.as_generic())
                .chain_update(
                    bincode::serialize(&(xrpc_uri, atp_user, atp_pass))
                        .context("Error serializing agent key")?,
                )
                .finalize()
                .into_bytes()
                .to_array(),
        ))
    }

    pub async fn login(&self, xrpc_uri: &Url, atp_user: &str, atp_pass: &str) -> Result<Agent> {
        let key = self.hash(xrpc_uri, atp_user, atp_pass)?;

        if let Some(agent) = self.0.agents.get(&key) {
            return Ok(Agent::new(agent.clone()));
        }

        debug!(%xrpc_uri, "Spawning new ATProto agent");

        let agent = AtpAgent::new(
            ReqwestClient::new(xrpc_uri.as_str().trim_end_matches('/')),
            MemorySessionStore::default(),
        );
        agent
            .login(atp_user, atp_pass)
            .await
            .with_context(|| format!("Error logging in as {atp_user:?}"))?;

        let agent = Arc::new(AgentInner {
            agent,
            dropped_at: None.into(),
        });
        self.0.agents.insert(key, Arc::clone(&agent));

        Ok(Agent::new(agent))
    }
}

// NOTE: phantom data is present to encourage using new()
#[derive(Clone)]
#[repr(transparent)]
pub struct Agent(Arc<AgentInner>, PhantomData<Infallible>);

struct AgentInner {
    agent: AtpAgent<MemorySessionStore, ReqwestClient>,
    dropped_at: parking_lot::Mutex<Option<Instant>>,
}

pub struct FeedCursor(String);

impl Drop for Agent {
    fn drop(&mut self) {
        let dropped_at = Instant::now();

        if Arc::strong_count(&self.0) <= 2 {
            *self.0.dropped_at.lock() = Some(dropped_at);
        }
    }
}

impl Agent {
    fn new(inner: Arc<AgentInner>) -> Self {
        *inner.dropped_at.lock() = None;

        Self(inner, PhantomData)
    }

    #[inline]
    fn agent(&self) -> &AtpAgent<MemorySessionStore, ReqwestClient> { &self.0.agent }

    pub async fn get_feed(&self, feed: AtProtoFeed, cursor: Option<FeedCursor>, limit: u8) -> Result {
        let cursor = cursor.map(|FeedCursor(c)| c);
        let limit = Some(limit.try_into().unwrap());

        let (cursor, feed) = match feed {
            AtProtoFeed::Home { algorithm } => self
                .agent()
                .api
                .app
                .bsky
                .feed
                .get_timeline(get_timeline::Parameters {
                    algorithm,
                    cursor,
                    limit,
                })
                .await
                .context("Error fetching home feed")
                .map(|get_timeline::Output { cursor, feed }| (cursor, feed)),

            AtProtoFeed::Gen { feed } => self
                .agent()
                .api
                .app
                .bsky
                .feed
                .get_feed(get_feed::Parameters {
                    cursor,
                    feed,
                    limit,
                })
                .await
                .context("Error fetching generated feed")
                .map(|get_feed::Output { cursor, feed }| (cursor, feed)),
        }?;

        debug!("{:x?}", feed.first());

        Ok(())
    }
}
