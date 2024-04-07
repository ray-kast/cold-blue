-- TODO: rename this to atp_actors or whatever
create table actors (
  id    uuid  primary key default gen_random_uuid(),
  owner uuid  not null references users (id),
  creds bytea not null
);
