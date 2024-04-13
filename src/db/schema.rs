// @generated automatically by Diesel CLI.

diesel::table! {
    credentials (id) {
        id -> Uuid,
        #[max_length = 256]
        name -> Nullable<Varchar>,
        owner -> Uuid,
        nonce -> Bytea,
        creds -> Bytea,
    }
}

diesel::table! {
    feeds (id) {
        id -> Uuid,
        owner -> Uuid,
        creds -> Nullable<Uuid>,
        params -> Nullable<Text>,
    }
}

diesel::table! {
    users (id) {
        id -> Uuid,
        #[max_length = 512]
        username -> Varchar,
        #[max_length = 512]
        password -> Varchar,
        superuser -> Bool,
        key_params -> Text,
    }
}

diesel::joinable!(credentials -> users (owner));
diesel::joinable!(feeds -> credentials (creds));
diesel::joinable!(feeds -> users (owner));

diesel::allow_tables_to_appear_in_same_query!(
    credentials,
    feeds,
    users,
);
