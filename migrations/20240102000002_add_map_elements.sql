-- Add map_elements table for tracking container IP to verdict mappings

CREATE TABLE map_elements (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  map_name        TEXT NOT NULL,
  element_key     BLOB NOT NULL,      -- IP address (stored as binary)
  element_value   TEXT NOT NULL,      -- verdict/chain name
  container_id    TEXT NOT NULL,
  created_at      TEXT NOT NULL DEFAULT (datetime('now')),
  
  UNIQUE(map_name, element_key),
  FOREIGN KEY(container_id) REFERENCES containers(id) ON DELETE CASCADE
) STRICT;

-- Create indexes for efficient lookups
CREATE INDEX idx_map_elements_container ON map_elements(container_id);
CREATE INDEX idx_map_elements_map_name ON map_elements(map_name);

-- Add a column to track map usage in persistent_rules
ALTER TABLE persistent_rules ADD COLUMN uses_maps INTEGER NOT NULL DEFAULT 0;