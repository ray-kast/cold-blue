// @generated automatically by Diesel CLI.

diesel::table! {
    actors (id) {
        id -> Uuid,
        owner -> Uuid,
        creds -> Bytea,
    }
}

diesel::table! {
    feeds (id) {
        id -> Uuid,
        actor -> Uuid,
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

diesel::joinable!(actors -> users (owner));
diesel::joinable!(feeds -> actors (actor));

diesel::allow_tables_to_appear_in_same_query!(
    actors,
    feeds,
    users,
);
