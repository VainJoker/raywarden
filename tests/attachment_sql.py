"""Exercise attachment metadata guards and late transaction rollback in SQLite."""

import sqlite3
import unittest

from sql_fixtures import (
    NOW, OLD, VAULT_REVISION, database, guard_sql, key_guard, row_guard, seed_attachment,
    seed_cipher, session_sql,
)
from sql_source import literal, source_literals, statements


class AttachmentFinalizationSql(unittest.TestCase):
    def setUp(self):
        self.db = database()
        self.addCleanup(self.db.close)
        seed_cipher(self.db, "cipher", data='{"name":"encrypted"}')
        seed_attachment(self.db, "attachment", "cipher", pending=True, name="encrypted-name", key="wrapped-key")
        self.db.execute("INSERT INTO devices(user_id,device_id,name,device_type,session_token,created_at,updated_at) VALUES('alice','device','test',1,'session',?,?)", (OLD, OLD))
        self.owner = dict(self.db.execute("SELECT * FROM users WHERE id='alice'").fetchone())
        self.cipher = dict(self.db.execute("SELECT * FROM ciphers WHERE id='cipher'").fetchone())
        self.pending = dict(self.db.execute("SELECT * FROM attachments_pending WHERE id='attachment'").fetchone())
        self.db.commit()
        self.batch = statements("attachment", "finalize_upload")
        self.assertEqual(len(self.batch), 3)

    def finalize(self):
        insert, remove, touch_cipher = self.batch
        pending_predicate = literal("attachment", "EXISTS(SELECT 1 FROM attachments_pending WHERE")
        pending_args = [self.pending[column] for column in ("id", "cipher_id", "file_name", "file_size_bytes", "encrypted_key", "created_at", "updated_at", "organization_id")]
        with self.db:
            self.db.execute(session_sql(), ("alice", "stamp", "device", "session")).fetchall()
            self.db.execute(*key_guard(self.owner)).fetchall()
            self.db.execute(*row_guard(self.cipher)).fetchall()
            self.db.execute(guard_sql(pending_predicate), pending_args).fetchall()
            self.db.execute(insert, ("attachment", "cipher", "encrypted-name", 15, "wrapped-key", OLD, NOW, None, "staged-object"))
            self.db.execute(remove, ("attachment",))
            self.db.execute(touch_cipher, (NOW, "cipher", "alice"))
            self.db.execute(VAULT_REVISION, (NOW, "alice")).fetchall()

    def test_finalize_moves_reservation_and_updates_only_owner_revisions(self):
        self.finalize()
        row = self.db.execute("SELECT file_size_bytes, encrypted_key, created_at, updated_at FROM attachments").fetchone()
        self.assertEqual(tuple(row), (15, "wrapped-key", OLD, NOW))
        self.assertEqual(self.db.execute("SELECT storage_key FROM attachments").fetchone()[0], "staged-object")
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM attachments_pending").fetchone()[0], 0)
        self.assertEqual(self.db.execute("SELECT updated_at FROM ciphers WHERE id='cipher'").fetchone()[0], NOW)
        users = dict(self.db.execute("SELECT id, updated_at FROM users"))
        self.assertEqual(users, {"alice": NOW, "bob": OLD})

    def test_database_failure_rolls_back_metadata_reservation_and_revisions(self):
        self.db.execute("CREATE TRIGGER reject_revision BEFORE UPDATE OF updated_at ON users BEGIN SELECT RAISE(ABORT, 'injected attachment cursor failure'); END")
        self.db.commit()
        with self.assertRaisesRegex(sqlite3.IntegrityError, "injected attachment cursor failure"):
            self.finalize()
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM attachments").fetchone()[0], 0)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM attachments_pending").fetchone()[0], 1)
        self.assertEqual(self.db.execute("SELECT updated_at FROM ciphers WHERE id='cipher'").fetchone()[0], OLD)
        self.assertEqual(dict(self.db.execute("SELECT id, updated_at FROM users")), {"alice": OLD, "bob": OLD})

    def replace(self, expected, key):
        update, touch = statements("attachment", "replace_upload")
        predicate = next(value for value in source_literals("attachment")
                         if value.startswith("EXISTS(SELECT 1 FROM attachments WHERE id=?1 AND cipher_id=?2")
                         and "storage_key IS ?9" in value)
        cipher = dict(self.db.execute("SELECT * FROM ciphers WHERE id='cipher'").fetchone())
        args = [expected[column] for column in ("id", "cipher_id", "file_name", "file_size_bytes", "encrypted_key", "created_at", "updated_at", "organization_id", "storage_key")]
        with self.db:
            self.db.execute(session_sql(), ("alice", "stamp", "device", "session")).fetchall()
            self.db.execute(*key_guard(self.owner)).fetchall()
            self.db.execute(*row_guard(cipher)).fetchall()
            self.db.execute(guard_sql(predicate), args).fetchall()
            self.db.execute(update, (18, "replacement-wrapped-key", key, NOW, "attachment", "cipher"))
            self.db.execute(touch, (NOW, "cipher", "alice"))
            self.db.execute(VAULT_REVISION, (NOW, "alice")).fetchall()

    def test_failed_ready_replacement_rolls_back_pointer_and_old_file_cleanup(self):
        self.finalize()
        old = dict(self.db.execute("SELECT * FROM attachments").fetchone())
        self.db.execute("CREATE TRIGGER reject_replacement_revision BEFORE UPDATE OF updated_at ON users BEGIN SELECT RAISE(ABORT, 'injected attachment cursor failure'); END")
        self.db.commit()
        with self.assertRaisesRegex(sqlite3.IntegrityError, "injected attachment cursor failure"):
            self.replace(old, "replacement-object")
        self.assertEqual(dict(self.db.execute("SELECT * FROM attachments").fetchone()), old)
        self.assertIsNone(self.db.execute("SELECT 1 FROM storage_cleanup_jobs WHERE object_key='staged-object'").fetchone())


if __name__ == "__main__":
    unittest.main(verbosity=2)
