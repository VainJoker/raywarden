-- Object write staging and durable deletion outbox.
-- Cleanup work has no account FK and survives account deletion.
-- All owning metadata tables exist before their lifecycle triggers are installed.

CREATE TABLE storage_cleanup_jobs (
    object_key TEXT PRIMARY KEY NOT NULL,
    created_at TEXT NOT NULL,
    generation TEXT NOT NULL DEFAULT (lower(hex(randomblob(16))))
);

CREATE TABLE storage_upload_stages (
    object_key TEXT PRIMARY KEY NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX idx_storage_upload_stages_expires_at_object_key
ON storage_upload_stages(julianday(expires_at), object_key);

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

-- Publication removes the stage after adopting the object in the same batch.
-- Aborted and expired stages have no metadata pointing to the staged key.
CREATE TRIGGER storage_upload_stages_delete_cleanup
AFTER DELETE ON storage_upload_stages
WHEN NOT EXISTS (SELECT 1 FROM attachments WHERE storage_key = OLD.object_key)
 AND NOT EXISTS (SELECT 1 FROM sends WHERE storage_key = OLD.object_key)
BEGIN
    INSERT INTO storage_cleanup_jobs(object_key, created_at)
    VALUES (OLD.object_key, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    ON CONFLICT(object_key) DO UPDATE SET created_at=excluded.created_at, generation=excluded.generation;
END;
