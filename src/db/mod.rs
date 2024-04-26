use std::{ops::Deref, time::Duration};

use deadpool::{managed::Timeouts, Runtime};
use diesel_async::{
    pooled_connection::{deadpool as pool, AsyncDieselConnectionManager, ManagerConfig},
    AsyncPgConnection,
};

use crate::prelude::*;

pub mod credentials;
mod schema;
pub mod user;

pub mod prelude {
    pub use diesel::{dsl as sql, pg::Pg, prelude::*};
    pub use diesel_async::RunQueryDsl;
    pub use uuid::Uuid;

    pub use super::{schema::*, Connection, Db};
}

pub type Connection = AsyncPgConnection;
pub type Manager = AsyncDieselConnectionManager<Connection>;
pub type Pool = pool::Pool<Connection>;
pub type PoolBuilder = pool::PoolBuilder<Connection>;
pub type PooledConnection = deadpool::managed::Object<Manager>;

#[derive(Debug, clap::Args)]
pub struct DbOpts {
    /// Database URL
    #[arg(long, env = "DATABASE_URL")]
    db_url: String,

    /// Database connection pool timeout
    #[arg(long, env, default_value_t = 10)]
    db_timeout: u64,
}

#[derive(Clone)]
#[repr(transparent)]
pub struct Db(Pool);

impl Db {
    pub fn new(opts: DbOpts) -> Result<Self> {
        let DbOpts { db_url, db_timeout } = opts;
        let db_timeout = Duration::from_secs(db_timeout);

        let mgr = Manager::new_with_config(db_url, ManagerConfig::default());

        let pool = Pool::builder(mgr)
            .runtime(Runtime::Tokio1)
            .timeouts(Timeouts {
                wait: Some(db_timeout),
                create: Some(db_timeout),
                recycle: Some(db_timeout),
            })
            .build()
            .context("Error building connection pool")?;

        Ok(Self(pool))
    }

    #[inline]
    pub async fn get(&self) -> Result<PooledConnection> {
        self.0
            .get()
            .await
            .context("Error acquiring database connection")
    }
}
