create table feeds (
  id    uuid  primary key default gen_random_uuid(),
  actor uuid  not null references actors (id)
);
