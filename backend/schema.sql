CREATE TABLE IF NOT EXISTS scans (
  id         TEXT PRIMARY KEY,
  domain     TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS scan_sources (
  scan_id    TEXT NOT NULL,
  source     TEXT NOT NULL,
  status     TEXT NOT NULL,
  found      INTEGER NOT NULL DEFAULT 0,
  error      TEXT,
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (scan_id, source)
);

CREATE TABLE IF NOT EXISTS subdomains (
  scan_id    TEXT NOT NULL,
  subdomain  TEXT NOT NULL,
  sources    TEXT NOT NULL,
  first_seen TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (scan_id, subdomain)
);

CREATE INDEX IF NOT EXISTS idx_subdomains_scan ON subdomains(scan_id);