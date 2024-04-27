use crate::prelude::*;

mod seed_superuser;
mod serve;

#[derive(Debug, clap::Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum Command {
    // TODO: migrate command
    SeedSuperuser(seed_superuser::SeedSuperuserCommand),
    Serve(serve::ServeCommand),
}

impl Command {
    #[inline]
    pub async fn run(self) -> Result {
        match self {
            Command::SeedSuperuser(s) => s.run().await,
            Command::Serve(s) => s.run().await,
        }
    }
}
