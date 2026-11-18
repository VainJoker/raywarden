-- Stable server signing keys. This row is independent of account deletion.
-- Runtime initialization creates the singleton only after a successful empty read.
CREATE TABLE jwt_keys (
    id TEXT PRIMARY KEY NOT NULL CHECK (id = 'global'),
    access_secret TEXT NOT NULL CHECK (length(access_secret) > 0),
    refresh_secret TEXT NOT NULL CHECK (length(refresh_secret) > 0)
);
