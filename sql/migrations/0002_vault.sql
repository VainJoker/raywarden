-- Personal vault, attachment metadata and domain matching.
-- File bytes live in object storage; global domain rows are cached at runtime.

-- Encrypted personal folders.
CREATE TABLE folders (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Encrypted vault entries; type-specific fields and item keys live in data.
CREATE TABLE ciphers (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT,
    organization_id TEXT,
    type INTEGER NOT NULL,
    data TEXT NOT NULL,
    favorite BOOLEAN NOT NULL DEFAULT 0,
    folder_id TEXT,
    deleted_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    archived_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE SET NULL
);

-- Completed attachment metadata; file contents are stored separately.
CREATE TABLE attachments (
    id TEXT PRIMARY KEY NOT NULL,
    cipher_id TEXT NOT NULL,
    file_name TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    akey TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    organization_id TEXT,
    FOREIGN KEY (cipher_id) REFERENCES ciphers(id) ON DELETE CASCADE
);

CREATE INDEX idx_attachments_cipher ON attachments(cipher_id);

-- Attachment reservations while uploads are in progress.
CREATE TABLE attachments_pending (
    id TEXT PRIMARY KEY NOT NULL,
    cipher_id TEXT NOT NULL,
    file_name TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    akey TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    organization_id TEXT,
    FOREIGN KEY (cipher_id) REFERENCES ciphers(id) ON DELETE CASCADE
);

CREATE INDEX idx_attachments_pending_cipher ON attachments_pending(cipher_id);

CREATE INDEX idx_attachments_pending_created_at ON attachments_pending(created_at);

-- Global URI-matching groups, populated and refreshed automatically at runtime.
CREATE TABLE global_equivalent_domains (
    type INTEGER PRIMARY KEY NOT NULL,
    sort_order INTEGER NOT NULL,
    domains_json TEXT NOT NULL
);

CREATE INDEX idx_global_equivalent_domains_sort_order
    ON global_equivalent_domains(sort_order);
