use crate::prelude::*;

/// Run the HTTP server
#[derive(Debug, clap::Args)]
pub struct ServeCommand {
    #[command(flatten)]
    server: crate::server::ServerOpts,
}

enum StopType<S> {
    Signal(S),
    Closed(Result<Result<(), std::io::Error>, tokio::task::JoinError>),
}

impl ServeCommand {
    pub async fn run(self) -> Result {
        let Self { server } = self;

        let server = crate::server::run(server).await?;
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

        // if shutdown {
        server.stop_tx.send(()).ok();
        // }

        ret
    }
}
