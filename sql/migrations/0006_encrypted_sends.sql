-- Encrypted Text/File Sends, access policies and upload state. Bytes live in object storage.

CREATE TABLE sends (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    notes TEXT,
    send_type INTEGER NOT NULL CHECK (send_type IN (0, 1)),
    data TEXT NOT NULL,
    encrypted_key TEXT NOT NULL,
    password_hash TEXT,
    password_salt TEXT,
    password_iterations INTEGER,
    max_access_count INTEGER CHECK (max_access_count IS NULL OR max_access_count >= 0),
    access_count INTEGER NOT NULL DEFAULT 0 CHECK (access_count >= 0),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    expires_at TEXT,
    deletes_at TEXT NOT NULL,
    is_disabled INTEGER NOT NULL DEFAULT 0,
    is_email_hidden INTEGER NOT NULL DEFAULT 0,
    access_stamp TEXT NOT NULL,
    file_id TEXT,
    file_size_bytes INTEGER NOT NULL DEFAULT 0 CHECK (file_size_bytes >= 0),
    upload_state INTEGER NOT NULL DEFAULT 0 CHECK (upload_state IN (0, 1, 2)),
    storage_key TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_sends_deletes_at ON sends(julianday(deletes_at));

CREATE INDEX idx_sends_created_at ON sends(julianday(created_at)) WHERE upload_state<>0;

CREATE INDEX idx_sends_user_id ON sends(user_id);
