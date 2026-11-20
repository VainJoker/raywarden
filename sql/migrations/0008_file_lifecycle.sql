-- Attachment metadata, upload reservations and durable object-deletion outbox.
-- Cleanup jobs deliberately have no account FK: they must survive account deletion.

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

CREATE TABLE storage_cleanup_jobs (
    object_key TEXT PRIMARY KEY NOT NULL,
    created_at TEXT NOT NULL,
    generation TEXT NOT NULL DEFAULT (lower(hex(randomblob(16))))
);

CREATE INDEX idx_attachments_cipher_id ON attachments(cipher_id);

CREATE INDEX idx_attachments_pending_cipher_id ON attachments_pending(cipher_id);

CREATE INDEX idx_attachments_pending_created_at ON attachments_pending(julianday(created_at));

CREATE INDEX idx_storage_cleanup_jobs_created_at_object_key ON storage_cleanup_jobs(created_at, object_key);

CREATE TRIGGER attachments_delete_storage
AFTER DELETE ON attachments
BEGIN
    INSERT INTO storage_cleanup_jobs(object_key, created_at)
    VALUES (COALESCE(OLD.storage_key, OLD.cipher_id || '/' || OLD.id), strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    ON CONFLICT(object_key) DO UPDATE SET created_at=excluded.created_at, generation=excluded.generation;
END;

CREATE TRIGGER attachments_replace_storage
AFTER UPDATE OF storage_key ON attachments
WHEN COALESCE(OLD.storage_key, OLD.cipher_id || '/' || OLD.id)
     != COALESCE(NEW.storage_key, NEW.cipher_id || '/' || NEW.id)
BEGIN
    INSERT INTO storage_cleanup_jobs(object_key, created_at)
    VALUES (COALESCE(OLD.storage_key, OLD.cipher_id || '/' || OLD.id), strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    ON CONFLICT(object_key) DO UPDATE SET created_at=excluded.created_at, generation=excluded.generation;
END;

CREATE TRIGGER pending_attachments_delete_storage
AFTER DELETE ON attachments_pending
BEGIN
    INSERT INTO storage_cleanup_jobs(object_key, created_at)
    VALUES (OLD.cipher_id || '/' || OLD.id, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    ON CONFLICT(object_key) DO UPDATE SET created_at=excluded.created_at, generation=excluded.generation;
END;

CREATE TRIGGER sends_delete_storage
AFTER DELETE ON sends
WHEN OLD.file_id IS NOT NULL
BEGIN
    INSERT INTO storage_cleanup_jobs(object_key, created_at)
    VALUES (COALESCE(OLD.storage_key, 'sends/' || OLD.id || '/' || OLD.file_id), strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    ON CONFLICT(object_key) DO UPDATE SET created_at=excluded.created_at, generation=excluded.generation;
END;

CREATE TRIGGER sends_replace_storage
AFTER UPDATE OF storage_key ON sends
WHEN OLD.file_id IS NOT NULL
 AND COALESCE(OLD.storage_key, 'sends/' || OLD.id || '/' || OLD.file_id)
     != COALESCE(NEW.storage_key, 'sends/' || NEW.id || '/' || NEW.file_id)
BEGIN
    INSERT INTO storage_cleanup_jobs(object_key, created_at)
    VALUES (COALESCE(OLD.storage_key, 'sends/' || OLD.id || '/' || OLD.file_id), strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    ON CONFLICT(object_key) DO UPDATE SET created_at=excluded.created_at, generation=excluded.generation;
END;
