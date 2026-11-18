-- Fresh object keys isolate upload attempts from the last committed file.
-- NULL keeps files written before this migration at their original paths.
ALTER TABLE attachments ADD COLUMN storage_key TEXT;
ALTER TABLE sends ADD COLUMN storage_key TEXT;

-- No account FK: cleanup must survive cascading account/vault deletion.
CREATE TABLE storage_cleanup_jobs (
    object_key TEXT PRIMARY KEY NOT NULL,
    created_at TEXT NOT NULL,
    generation TEXT NOT NULL DEFAULT (lower(hex(randomblob(16))))
);

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
