use std::io::{stderr, stdin, IsTerminal, Read};

use arrayvec::CapacityError;
use diesel_async::{scoped_futures::ScopedFutureExt, RunQueryDsl};

use crate::{
    db::{
        prelude::*,
        user::{Password, User, Username},
        Db, DbOpts,
    },
    prelude::*,
};

/// Add a superuser to the database if none exist
#[derive(Debug, clap::Args)]
pub struct SeedSuperuserCommand {
    /// Username of the account to add
    #[arg(required = !(stdin().is_terminal() && stderr().is_terminal()))]
    username: Option<Username>,

    #[command(flatten)]
    db: DbOpts,
}

impl SeedSuperuserCommand {
    pub async fn run(self) -> Result {
        let Self { db, username } = self;

        let db = Db::new(db).context("Error initializing database")?;
        let mut conn = db.get().await.context("Error connecting to database")?;

        conn.build_transaction()
            .read_write()
            .read_committed()
            .run(|conn| {
                async move {
                    let exists = users::table
                        .filter(users::superuser)
                        .select(users::superuser)
                        .first::<bool>(conn)
                        .await
                        .optional()
                        .context("Error querying database for superusers")?;

                    if exists == Some(true) {
                        bail!("Database contains a superuser, quitting");
                    }

                    let username = if let Some(u) = username {
                        u
                    } else {
                        eprint!("Enter the username of the new account: ");
                        let mut s = String::new();
                        stdin()
                            .read_line(&mut s)
                            .context("Error reading username from terminal")?;

                        let username = Username::from(s.trim())
                            .map_err(CapacityError::simplify)
                            .context("Invalid username")?;
                        eprintln!("Username: {username:?}");

                        username
                    };

                    let password = if stdin().is_terminal() && stderr().is_terminal() {
                        let pw =
                            rpassword::prompt_password("Enter the password for the new account: ")
                                .context("Error reading password from terminal")?;

                        let pw2 =
                            rpassword::prompt_password("Confirm the password for the account: ")
                                .context("Error confirming password from terminal")?;

                        ensure!(pw == pw2, "Passwords don't match");
                        pw
                    } else {
                        let mut s = String::new();
                        stdin()
                            .read_to_string(&mut s)
                            .context("Error reading password from stdin")?;

                        info!("Read {} password byte(s) from stdin", s.len());
                        s
                    };

                    let password = Password::from(&password)
                        .map_err(CapacityError::simplify)
                        .context("Invalid password")?;

                    let id = User::create(conn, &username, &password, true).await?;

                    info!(%id, "User successfully created");

                    Ok(())
                }
                .scope_boxed()
            })
            .await
    }
}
