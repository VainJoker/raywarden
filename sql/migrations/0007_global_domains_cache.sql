-- A single shared retry/refresh deadline; the dataset lives in the existing
-- global_equivalent_domains table. The first reader claims and populates it.
CREATE TABLE global_domains_cache (
    id INTEGER PRIMARY KEY NOT NULL CHECK (id = 1),
    next_refresh_at INTEGER NOT NULL
);
