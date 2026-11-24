-- Personal folders and encrypted vault entries. Every entry has an account owner.

CREATE TABLE folders (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE ciphers (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    organization_id TEXT,
    cipher_type INTEGER NOT NULL CHECK (cipher_type BETWEEN 1 AND 8),
    data TEXT NOT NULL,
    is_favorite BOOLEAN NOT NULL DEFAULT 0 CHECK (is_favorite IN (0, 1)),
    folder_id TEXT,
    deleted_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    archived_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE SET NULL
);

CREATE INDEX idx_folders_user_id ON folders(user_id);

CREATE INDEX idx_ciphers_user_id ON ciphers(user_id);

CREATE INDEX idx_ciphers_folder_id ON ciphers(folder_id) WHERE folder_id IS NOT NULL;

CREATE INDEX idx_ciphers_deleted_at ON ciphers(julianday(deleted_at)) WHERE deleted_at IS NOT NULL;

-- Keep SET NULL on folder deletion while enforcing ownership on every write.
CREATE TRIGGER ciphers_folder_owner_insert
BEFORE INSERT ON ciphers
WHEN NEW.folder_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM folders WHERE id=NEW.folder_id AND user_id=NEW.user_id
)
BEGIN
    SELECT RAISE(ABORT, 'Folder does not belong to cipher owner');
END;

CREATE TRIGGER ciphers_folder_owner_update
BEFORE UPDATE OF folder_id, user_id ON ciphers
WHEN NEW.folder_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM folders WHERE id=NEW.folder_id AND user_id=NEW.user_id
)
BEGIN
    SELECT RAISE(ABORT, 'Folder does not belong to cipher owner');
END;

CREATE TRIGGER folders_owner_immutable
BEFORE UPDATE OF user_id ON folders
WHEN NEW.user_id != OLD.user_id
BEGIN
    SELECT RAISE(ABORT, 'Folder owner cannot change');
END;

-- Attachment metadata and reservations; ciphertext lives in object storage.
CREATE TABLE attachments (
    id TEXT PRIMARY KEY NOT NULL,
    cipher_id TEXT NOT NULL,
    file_name TEXT NOT NULL,
    file_size_bytes INTEGER NOT NULL CHECK (file_size_bytes >= 0),
    encrypted_key TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    organization_id TEXT,
    storage_key TEXT,
    FOREIGN KEY (cipher_id) REFERENCES ciphers(id) ON DELETE CASCADE
);

CREATE TABLE attachments_pending (
    id TEXT PRIMARY KEY NOT NULL,
    cipher_id TEXT NOT NULL,
    file_name TEXT NOT NULL,
    file_size_bytes INTEGER NOT NULL CHECK (file_size_bytes >= 0),
    encrypted_key TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    organization_id TEXT,
    FOREIGN KEY (cipher_id) REFERENCES ciphers(id) ON DELETE CASCADE
);

CREATE INDEX idx_attachments_cipher_id ON attachments(cipher_id);

CREATE INDEX idx_attachments_pending_cipher_id ON attachments_pending(cipher_id);

CREATE INDEX idx_attachments_pending_created_at ON attachments_pending(julianday(created_at));


-- Object-key lookups used by storage cleanup and publication.
CREATE INDEX idx_attachments_effective_object_key
ON attachments(COALESCE(storage_key, cipher_id || '/' || id));

CREATE INDEX idx_attachments_storage_key
ON attachments(storage_key) WHERE storage_key IS NOT NULL;
