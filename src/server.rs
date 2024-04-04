use std::time::Duration;

use axum::Router;
use listenfd::ListenFd;
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};
use tower_http::{timeout::TimeoutLayer, trace::TraceLayer};

use crate::prelude::*;

mod handlers;

const DEFAULT_ADDR: &str = "[::]:3000";

#[derive(Debug, clap::Args)]
pub struct ServerOpts {
    /// The address to bind to
    #[arg(long, env, default_value = DEFAULT_ADDR)]
    listen_on: String,

    /// Timeout for HTTP request handlers
    #[arg(long, env, default_value = "10")]
    response_timeout: u64,
}

pub struct Server {
    pub handle: JoinHandle<Result<(), std::io::Error>>,
    pub stop_tx: oneshot::Sender<()>,
}

fn app<S: Clone + Send + Sync + 'static>(opts: &ServerOpts) -> Router<S> {
    use axum::routing::*;

    let ServerOpts {
        response_timeout, ..
    } = *opts;

    Router::new()
        .route(handlers::INDEX_ROUTE, get(handlers::index))
        .route(handlers::LOGIN_ROUTE, get(handlers::get_login).post(handlers::post_login))
        .fallback(handlers::fallback)
        .layer((
            TraceLayer::new_for_http(),
            TimeoutLayer::new(Duration::from_secs(response_timeout)),
        ))
}

#[instrument(level = "error", name = "server", skip(opts))]
pub async fn run(opts: ServerOpts) -> Result<Server> {
    let app = app(&opts);
    let ServerOpts { listen_on, .. } = opts;

    let mut listenfd = ListenFd::from_env();
    let sock = listenfd
        .take_tcp_listener(0)
        .context("Error taking listenfd listener")?;
    let listener = if let Some(sock) = sock {
        if listen_on != DEFAULT_ADDR {
            warn!(
                ?listen_on,
                "systemfd socket supplied, ignoring configured socket address"
            );
        }

        sock.set_nonblocking(true)
            .context("Error setting nonblock on listenfd socket")?;
        TcpListener::from_std(sock).context("Error lifting listenfd socket")?
    } else {
        let sock = TcpListener::bind(&listen_on)
            .await
            .with_context(|| format!("Error binding to {listen_on:?}"))?;
        info!("Listening on {listen_on:?}...");
        sock
    };

    let (stop_tx, rx) = tokio::sync::oneshot::channel();

    let handle = tokio::spawn(
        async move {
            // TODO: why does this need to be wrapped in an async block?
            axum::serve(listener, app)
                .with_graceful_shutdown(rx.map_ok_or_else(|_| (), |()| ()))
                .await
        }
        .in_current_span(),
    );

    Ok(Server { handle, stop_tx })
}
