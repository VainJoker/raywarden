-- Encrypted Text/File Sends, access policy and pending upload state.
-- File bytes live in object storage.

CREATE TABLE sends (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    notes TEXT,
    type INTEGER NOT NULL CHECK (type IN (0, 1)),
    data TEXT NOT NULL,
    akey TEXT NOT NULL,
    password_hash TEXT,
    password_salt TEXT,
    password_iter INTEGER,
    max_access_count INTEGER CHECK (max_access_count IS NULL OR max_access_count >= 0),
    access_count INTEGER NOT NULL DEFAULT 0 CHECK (access_count >= 0),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    expiration_date TEXT,
    deletion_date TEXT NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0,
    hide_email INTEGER NOT NULL DEFAULT 0,
    access_stamp TEXT NOT NULL,
    file_id TEXT,
    file_size INTEGER NOT NULL DEFAULT 0 CHECK (file_size >= 0),
    pending INTEGER NOT NULL DEFAULT 0 CHECK (pending IN (0, 1, 2)),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_sends_deletion_date ON sends(deletion_date);

CREATE INDEX idx_sends_pending ON sends(pending, created_at);

CREATE INDEX idx_sends_user_id ON sends(user_id);
