use crate::{db::prelude::*, prelude::*};

mod params;

pub use params::{AtProtoFeed, FeedParams};

#[derive(Queryable, Insertable)]
#[diesel(check_for_backend(Pg))]
pub struct Feed {
    id: Uuid,
    owner: Uuid,
    name: String,
    creds: Option<Uuid>,
    params: Value,
}

impl Feed {
    pub async fn create<P: Into<params::FeedParams>>(
        db: &mut Connection,
        owner: Uuid,
        name: String,
        creds: Option<Uuid>,
        params: P,
    ) -> Result<Self> {
        let feed = Self {
            id: Uuid::new_v4(),
            owner,
            name,
            creds,
            params: serde_json::to_value(params.into())
                .context("Error serializing feed parameters")?,
        };

        (&feed)
            .insert_into(feeds::table)
            .execute(db)
            .await
            .context("Error storing feed in database")?;

        Ok(feed)
    }

    pub async fn from_owner(db: &mut Connection, owner: &Uuid) -> Result<Vec<Self>> {
        feeds::table
            .filter(feeds::owner.eq(owner))
            .load(db)
            .await
            .context("Error querying feeds by owner")
    }

    #[inline]
    pub fn id(&self) -> &Uuid { &self.id }

    #[inline]
    pub fn name(&self) -> &str { &self.name }

    // TODO: don't expose this directly
    #[inline]
    pub fn params(&self) -> &Value { &self.params }
}
