//! Entry point for `cold-blue`

// TODO: this is basically a duplicate of the-q/entry.rs, can this be made into
//       a utility crate?

#![deny(
    clippy::disallowed_methods,
    clippy::suspicious,
    clippy::style,
    clippy::clone_on_ref_ptr,
    missing_debug_implementations,
    missing_copy_implementations
)]
#![warn(clippy::pedantic, missing_docs)]
#![allow(clippy::module_name_repetitions)]

pub(crate) mod server;
pub(crate) mod agent;

pub(crate) mod prelude {
    #![allow(unused_imports)]

    pub use std::{
        borrow::{
            Borrow, BorrowMut, Cow,
            Cow::{Borrowed, Owned},
        },
        collections::{BTreeMap, BTreeSet, HashMap, HashSet},
        convert::Infallible,
        fmt,
        future::Future,
        hash::Hash,
        marker::PhantomData,
        mem,
        str::FromStr,
        sync::Arc,
    };

    pub use anyhow::{anyhow, bail, ensure, Context as _, Error};
    pub use futures_util::{FutureExt, StreamExt, TryFutureExt, TryStreamExt};
    pub use tracing::{
        debug, debug_span, error, error_span, info, info_span, instrument, trace, trace_span, warn,
        warn_span, Instrument,
    };
    pub use tracing_subscriber::prelude::*;
    pub use url::Url;

    pub type Result<T = (), E = Error> = std::result::Result<T, E>;
}

mod entry {
    use tracing_subscriber::{layer::Layered, EnvFilter};

    use crate::prelude::*;

    #[derive(Debug, clap::Parser)]
    #[command(version, author, about)]
    struct Opts {
        /// Log filter, using env_logger-like syntax
        #[arg(long, env = "RUST_LOG", default_value = "info")]
        log_filter: String,

        /// Grafana Loki endpoint to use
        #[arg(long, env)]
        loki_endpoint: Option<Url>,

        /// Hint for the number of threads to use
        #[arg(short = 'j', long, env)]
        threads: Option<usize>,

        #[command(flatten)]
        server: crate::server::ServerOpts,

        #[command(flatten)]
        agent: crate::agent::AgentOpts,
    }

    macro_rules! init_error {
        ($($args:tt)*) => ({
            ::tracing::error!($($args)*);
            ::std::process::exit(1);
        })
    }

    fn fmt_layer<S>() -> tracing_subscriber::fmt::Layer<S> { tracing_subscriber::fmt::layer() }

    #[instrument(name = "init_logger", skip(log_filter, f))]
    fn init_subscriber<
        S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    >(
        log_filter: impl AsRef<str>,
        f: impl FnOnce(Layered<EnvFilter, tracing_subscriber::Registry>) -> S,
    ) where
        Layered<tracing_subscriber::fmt::Layer<S>, S>: Into<tracing::Dispatch>,
    {
        let log_filter = log_filter.as_ref();
        let reg = tracing_subscriber::registry().with(
            EnvFilter::try_new(log_filter)
                .unwrap_or_else(|e| init_error!("Invalid log filter {log_filter:?}: {e}")),
        );

        f(reg)
            .with(fmt_layer())
            .try_init()
            .unwrap_or_else(|e| init_error!("Error initializing logger: {e}"));
    }

    #[inline]
    pub fn main() {
        let tmp_logger =
            tracing::subscriber::set_default(tracing_subscriber::registry().with(fmt_layer()));
        let span = error_span!("boot").entered();

        [
            ".env.local",
            if cfg!(debug_assertions) {
                ".env.dev"
            } else {
                ".env.prod"
            },
            ".env",
        ]
        .into_iter()
        .try_for_each(|p| match dotenvy::from_filename(p) {
            Ok(p) => {
                trace!("Loaded env from {p:?}");
                Ok(())
            },
            Err(dotenvy::Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).with_context(|| format!("Error loading env from {p:?}")),
        })
        .unwrap_or_else(|e| init_error!("Error loading .env files: {e:?}"));

        let opts: Opts = clap::Parser::parse();
        drop(span);
        let span = error_span!("boot", ?opts).entered();

        let hostname = hostname::get()
            .context("Error loading hostname")
            .and_then(|h| {
                h.into_string()
                    .map_err(|s| anyhow!("Couldn't parse hostname {s:?}"))
            })
            .unwrap_or_else(|e| init_error!("Error getting system hostname: {e}"));

        let loki_task = if let Some(endpoint) = &opts.loki_endpoint {
            let (layer, task) = tracing_loki::layer(
                endpoint.clone(),
                [
                    ("host".into(), hostname),
                    ("crate".into(), env!("CARGO_PKG_NAME").into()),
                ]
                .into_iter()
                .collect(),
                [].into_iter().collect(),
            )
            .unwrap_or_else(|err| init_error!(%err, "Error initializing Loki exporter"));

            init_subscriber(&opts.log_filter, |r| r.with(layer));
            Some(task)
        } else {
            init_subscriber(&opts.log_filter, |r| r);
            None
        };

        drop((span, tmp_logger));

        let rt = {
            let mut builder = tokio::runtime::Builder::new_multi_thread();

            if let Some(threads) = opts.threads {
                builder
                    .worker_threads(threads)
                    .max_blocking_threads(threads * 2);
            }

            builder
                .enable_all()
                .build()
                .unwrap_or_else(|e| init_error!("Async runtime setup error: {e}"))
        };

        let def = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |inf| {
            use std::any::Any;

            fn downcast(payload: &dyn Any) -> &str {
                if let Some(s) = payload.downcast_ref::<&'static str>() {
                    return s;
                }

                if let Some(s) = payload.downcast_ref::<String>() {
                    return s.as_str();
                }

                "Box<dyn Any>"
            }

            def(inf);

            let thread = std::thread::current();
            let location = inf.location().map_or_else(String::new, ToString::to_string);
            let payload = downcast(inf.payload());

            error!(name = thread.name(), payload, %location, "Thread panicked!");
        }));

        loki_task.map(|t| rt.spawn(t));

        std::process::exit(match rt.block_on(run(opts)) {
            Ok(()) => 0,
            Err(e) => {
                error!("{e:?}");
                1
            },
        });
    }

    enum StopType<S> {
        Signal(S),
        Closed(Result<Result<(), std::io::Error>, tokio::task::JoinError>),
    }

    #[allow(clippy::inline_always)]
    #[inline(always)]
    #[instrument(level = "error", skip(opts))]
    async fn run(opts: Opts) -> Result {
        let Opts {
            log_filter: _,
            loki_endpoint: _,
            threads: _,
            server,
            agent,
        } = opts;

        let (server, agent) = tokio::join!(
            crate::server::run(server),
            crate::agent::run(agent),
        );
        let server = server?;
        let () = agent?;
        let signal;

        #[cfg(unix)]
        {
            use futures_util::stream::FuturesUnordered;
            use tokio::signal::unix::SignalKind;

            let mut stream = [
                SignalKind::hangup(),
                SignalKind::interrupt(),
                SignalKind::quit(),
                SignalKind::terminate(),
            ]
            .into_iter()
            .map(|k| {
                tokio::signal::unix::signal(k)
                    .with_context(|| format!("Error hooking signal {k:?}"))
                    .map(|mut s| async move {
                        s.recv().await;
                        Result::<_>::Ok(k)
                    })
            })
            .collect::<Result<FuturesUnordered<_>>>()?;

            signal = async move { stream.next().await.transpose() }
        }

        #[cfg(not(unix))]
        {
            use std::fmt;

            use futures_util::TryFutureExt;

            struct CtrlC;

            impl fmt::Debug for CtrlC {
                fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("^C") }
            }

            signal = tokio::signal::ctrl_c()
                .map_ok(|()| Some(CtrlC))
                .map_err(Into::into);
        }

        let ret = tokio::select! {
            s = signal => StopType::Signal(s),
            r = server.handle => StopType::Closed(r),
        };

        // let shutdown = !matches!(ret, StopType::Closed(Err(_)));
        let shutdown = true;

        let ret = match ret {
            StopType::Signal(Ok(Some(s))) => {
                warn!("{s:?} received, shutting down...");
                Ok(())
            },
            StopType::Signal(Ok(None)) => Err(anyhow!("Unexpected error from signal handler")),
            StopType::Signal(Err(e)) => Err(e),
            StopType::Closed(Err(e)) => Err(e).context("Server task panicked"),
            StopType::Closed(Ok(Err(e))) => Err(e).context("Fatal server error occurred"),
            StopType::Closed(Ok(Ok(()))) => Err(anyhow!("Server hung up unexpectedly")),
        };

        if shutdown {
            server.stop_tx.send(()).ok();
        }

        ret
    }
}

fn main() { entry::main() }
