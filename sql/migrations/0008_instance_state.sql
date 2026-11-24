-- Instance signing keys and shared global-domain cache. Independent of account deletion.

CREATE TABLE jwt_keys (
    id TEXT PRIMARY KEY NOT NULL CHECK (id = 'global'),
    access_secret TEXT NOT NULL CHECK (length(access_secret) > 0),
    refresh_secret TEXT NOT NULL CHECK (length(refresh_secret) > 0)
);

CREATE TABLE global_equivalent_domains (
    type INTEGER PRIMARY KEY NOT NULL,
    sort_order INTEGER NOT NULL,
    domains_json TEXT NOT NULL
);

CREATE TABLE global_domains_cache (
    id INTEGER PRIMARY KEY NOT NULL CHECK (id = 1),
    next_refresh_at INTEGER NOT NULL
);

CREATE INDEX idx_global_equivalent_domains_sort_order
    ON global_equivalent_domains(sort_order);
