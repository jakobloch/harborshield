-- Initial schema for harborshield database

CREATE TABLE containers (
  id   TEXT PRIMARY KEY,
  name TEXT UNIQUE NOT NULL
) STRICT;

CREATE TABLE addrs (
  addr         BLOB PRIMARY KEY,
  container_id TEXT NOT NULL,

  FOREIGN KEY(container_id) REFERENCES containers(id)
) STRICT;

CREATE TABLE container_aliases (
  container_id    TEXT NOT NULL,
  container_alias TEXT NOT NULL,

  PRIMARY KEY(container_id, container_alias),
  FOREIGN KEY(container_id) REFERENCES containers(id)
) STRICT;

CREATE TABLE est_containers (
  src_container_id TEXT NOT NULL,
  dst_container_id TEXT NOT NULL,

  PRIMARY KEY(src_container_id, dst_container_id),
  FOREIGN KEY(src_container_id) REFERENCES containers(id),
  FOREIGN KEY(dst_container_id) REFERENCES containers(id)
) STRICT;

CREATE TABLE waiting_container_rules (
  src_container_id   TEXT    NOT NULL,
  dst_container_name TEXT    NOT NULL,
  rule               BLOB    NOT NULL,

  PRIMARY KEY(src_container_id, dst_container_name, rule),
  FOREIGN KEY (src_container_id) REFERENCES containers(id)
) STRICT;

CREATE TABLE persistent_rules (
  id            TEXT PRIMARY KEY,
  container_id  TEXT NOT NULL,
  rule_type     TEXT NOT NULL,
  rule_config   TEXT NOT NULL,
  rule_data     BLOB NOT NULL,
  created_at    TEXT NOT NULL,
  enabled       INTEGER NOT NULL DEFAULT 1,

  FOREIGN KEY(container_id) REFERENCES containers(id)
) STRICT;

CREATE TABLE shutdown_state (
  id                    INTEGER PRIMARY KEY AUTOINCREMENT,
  shutdown_time         TEXT NOT NULL,
  harborshield_version     TEXT NOT NULL,
  config_snapshot       TEXT NOT NULL,
  active_containers     INTEGER NOT NULL,
  active_rules          INTEGER NOT NULL,
  metrics_snapshot      TEXT
) STRICT;

CREATE TABLE container_state_snapshot (
  shutdown_id     INTEGER NOT NULL,
  container_id    TEXT NOT NULL,
  container_name  TEXT NOT NULL,
  state_json      TEXT NOT NULL,
  
  PRIMARY KEY(shutdown_id, container_id),
  FOREIGN KEY(shutdown_id) REFERENCES shutdown_state(id),
  FOREIGN KEY(container_id) REFERENCES containers(id)
) STRICT;

CREATE TABLE rule_state_snapshot (
  shutdown_id     INTEGER NOT NULL,
  rule_id         TEXT NOT NULL,
  container_id    TEXT NOT NULL,
  rule_type       TEXT NOT NULL,
  rule_json       TEXT NOT NULL,
  
  PRIMARY KEY(shutdown_id, rule_id),
  FOREIGN KEY(shutdown_id) REFERENCES shutdown_state(id)
) STRICT;