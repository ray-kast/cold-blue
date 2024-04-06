use std::{path::PathBuf, time::Duration};

use listenfd::ListenFd;
use poem::{
    listener::{Listener, TcpAcceptor, TcpListener},
    middleware::{Compression, Tracing},
    EndpointExt, Server,
};
use tokio::{sync::oneshot, task::JoinHandle};

use self::session::SessionManager;
use crate::prelude::*;

mod creds;
mod handlers;
mod locale;
mod session;
mod user;

const DEFAULT_ADDR: &str = "[::]:3000";

#[derive(Debug, clap::Args)]
pub struct ServerOpts {
    /// The address to bind to
    #[arg(long, env, default_value = DEFAULT_ADDR)]
    listen_on: String,

    /// Timeout for HTTP request handlers
    #[arg(long, env, default_value = "10")]
    shutdown_timeout: u64,

    /// PEM file containing an EdDSA key for JWT signing
    #[arg(long, env)]
    jwt_key: PathBuf,

    /// base64-encoded encryption key for JWT encryption
    #[arg(long, env)]
    session_key: String,
}

pub struct ServerHandle {
    pub handle: JoinHandle<Result<(), std::io::Error>>,
    pub stop_tx: oneshot::Sender<()>,
}

#[instrument(level = "error", name = "server", skip(opts))]
pub async fn run(opts: ServerOpts) -> Result<ServerHandle> {
    let ServerOpts {
        listen_on,
        shutdown_timeout,
        jwt_key,
        session_key,
    } = opts;

    let sessions =
        SessionManager::new(jwt_key, &session_key).context("Error initializing session manager")?;

    let mut listenfd = ListenFd::from_env();
    let sock = listenfd
        .take_tcp_listener(0)
        .context("Error taking listenfd listener")?;
    let acceptor = if let Some(sock) = sock {
        if listen_on != DEFAULT_ADDR {
            warn!(
                ?listen_on,
                "systemfd socket supplied, ignoring configured socket address"
            );
        }

        sock.set_nonblocking(true)
            .context("Error setting nonblock on listenfd socket")?;
        TcpAcceptor::from_std(sock).context("Error lifting listenfd socket")?
    } else {
        let sock = TcpListener::bind(&listen_on)
            .into_acceptor()
            .await
            .with_context(|| format!("Error binding to {listen_on:?}"))?;
        info!("Listening on {listen_on:?}...");
        sock
    };

    let (stop_tx, rx) = tokio::sync::oneshot::channel();

    let handle = tokio::spawn(
        async move {
            // TODO: why does this need to be wrapped in an async block?
            Server::new_with_acceptor(acceptor)
                .run_with_graceful_shutdown(
                    handlers::route(sessions).with((Tracing, Compression::new())),
                    rx.map_ok_or_else(|_| (), |()| ()),
                    Some(Duration::from_secs(shutdown_timeout)),
                )
                .await
        }
        .in_current_span(),
    );

    Ok(ServerHandle { handle, stop_tx })
}
