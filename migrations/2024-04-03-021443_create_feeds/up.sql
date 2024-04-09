create table feeds (
  id      uuid  primary key default gen_random_uuid(),
  owner   uuid  not null references users (id),
  creds   uuid  null references credentials (id),
  params  text  null
);
