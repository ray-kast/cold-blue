create table users (
  id          uuid          primary key default gen_random_uuid(),
  username    varchar(512)  unique not null,
  password    varchar(512)  not null,
  superuser   boolean       not null,
  key_params  text          not null
);
