#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub enum FeedParams {
    AtProto(AtProtoFeed),
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub enum AtProtoFeed {
    Home { algorithm: Option<String> },
    Gen { feed: String },
}
