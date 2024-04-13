create table credentials (
  id    uuid          primary key default gen_random_uuid(),
  name  varchar(256),
  owner uuid          not null references users (id),
  nonce bytea         not null,
  creds bytea         not null
);
