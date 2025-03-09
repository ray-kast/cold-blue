create table credentials (
  id    uuid          primary key default gen_random_uuid(),
  owner uuid          not null references users (id),
  name  varchar(256)  not null,
  nonce bytea         not null,
  creds bytea         not null,

  unique (owner, name)
);
