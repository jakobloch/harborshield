-- Remove persistence-related tables
DROP TABLE IF EXISTS rule_state_snapshot;
DROP TABLE IF EXISTS container_state_snapshot;
DROP TABLE IF EXISTS shutdown_state;
DROP TABLE IF EXISTS persistent_rules;
DROP TABLE IF EXISTS map_elements;