create table feeds (
  id      uuid          primary key default gen_random_uuid(),
  owner   uuid          not null references users (id),
  name    varchar(256)  not null,
  creds   uuid          null references credentials (id),
  params  jsonb         not null,

  unique (owner, name)
);
