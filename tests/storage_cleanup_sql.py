"""Run deletion triggers and the Rust outbox SQL against real SQLite."""
import json
import sqlite3
import unittest

from sql_fixtures import apply_migrations
from sql_source import statement


class StorageCleanupSql(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        self.db.execute("PRAGMA foreign_keys=ON")
        apply_migrations(self.db)
        self.db.execute("INSERT INTO users(id,email,master_password_hash,key,private_key,public_key,created_at,updated_at) VALUES('u','owner@example.test','hash','key','private','public','old','old')")
        self.db.execute("INSERT INTO ciphers(id,user_id,cipher_type,data,created_at,updated_at) VALUES('c','u',1,'{}','old','old')")
        self.db.execute("INSERT INTO attachments(id,cipher_id,file_name,file_size_bytes,created_at,updated_at) VALUES('a','c','encrypted',5,'old','old')")
        self.db.execute("INSERT INTO sends(id,user_id,name,send_type,data,encrypted_key,created_at,updated_at,deletes_at,access_stamp,file_id) VALUES('s','u','encrypted',1,'{}','key','old','old','future','stamp','f')")
        self.enqueue = statement("storage_cleanup", "enqueue_if_unreferenced")
        self.select = statement("storage_cleanup", "pending_batch")
        self.ack = statement("storage_cleanup", "acknowledge_prefix")

    def test_adopted_files_are_never_discarded_after_an_ambiguous_response(self):
        for key in ['c/a', 'sends/s/f']:
            self.assertEqual(self.db.execute(self.enqueue, (key, 'now')).rowcount, 0)
        self.db.execute("UPDATE attachments SET storage_key='random-attempt' WHERE id='a'")
        self.assertEqual(self.db.execute(self.enqueue, ('random-attempt', 'now')).rowcount, 0)
        self.assertEqual(self.db.execute(self.enqueue, ('failed-attempt', 'now')).rowcount, 1)
        self.assertIn('failed-attempt', {r[0] for r in self.db.execute(self.select)})

    def test_replacements_queue_only_the_previous_object(self):
        self.db.execute("UPDATE attachments SET storage_key='a-new' WHERE id='a'")
        self.db.execute("UPDATE sends SET storage_key='s-new' WHERE id='s'")
        self.assertEqual({r[0] for r in self.db.execute(self.select)}, {'c/a', 'sends/s/f'})
        self.db.execute("UPDATE attachments SET storage_key='a-new' WHERE id='a'")
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM storage_cleanup_jobs").fetchone()[0], 2)

    def test_account_cascade_retains_jobs_without_an_account_foreign_key(self):
        self.db.execute("INSERT INTO attachments_pending(id,cipher_id,file_name,file_size_bytes,created_at,updated_at) VALUES('p','c','pending',7,'old','old')")
        self.db.execute("DELETE FROM users WHERE id='u'")
        self.assertEqual({r[0] for r in self.db.execute(self.select)}, {'c/a', 'c/p', 'sends/s/f'})
        self.assertEqual(self.db.execute('PRAGMA foreign_key_check').fetchall(), [])

    def test_finalized_legacy_object_is_protected_from_pending_delete_job(self):
        self.db.execute("INSERT INTO attachments_pending(id,cipher_id,file_name,file_size_bytes,created_at,updated_at) VALUES('a','c','pending',5,'old','old')")
        self.db.execute("DELETE FROM attachments_pending WHERE id='a'")
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM storage_cleanup_jobs").fetchone()[0], 1)
        self.assertEqual(self.db.execute(self.select).fetchall(), [])

    def test_acknowledgement_cannot_remove_a_new_generation_of_the_job(self):
        self.db.execute(self.enqueue, ('failed-attempt', 'now'))
        key, generation = self.db.execute(self.select).fetchone()
        self.db.execute(self.enqueue, ('failed-attempt', 'now'))
        snapshot = json.dumps([{'object_key': key, 'generation': generation}])
        self.assertEqual(self.db.execute(self.ack, (snapshot,)).rowcount, 0)
        current = self.db.execute(self.select).fetchone()
        self.assertNotEqual(current[1], generation)
        self.assertEqual(self.db.execute(self.ack, (json.dumps([{'object_key': current[0], 'generation': current[1]}]),)).rowcount, 1)

    def test_reference_queries_use_effective_and_staged_object_key_indexes(self):
        def plan(sql, args=()):
            return "\n".join(row[3] for row in self.db.execute("EXPLAIN QUERY PLAN " + sql, args))

        for details in (plan(self.select), plan(self.enqueue, ("stage-key", "now"))):
            for table in ("attachments", "sends"):
                self.assertIn(f"idx_{table}_effective_object_key", details)
                self.assertNotIn(f"SCAN {table}", details)
        trigger = self.db.execute("SELECT sql FROM sqlite_schema WHERE name='storage_upload_stages_delete_cleanup'").fetchone()[0]
        for table in ("attachments", "sends"):
            probe = f"SELECT 1 FROM {table} WHERE storage_key = OLD.object_key"
            self.assertIn(probe, trigger)
            self.assertIn(f"idx_{table}_storage_key", plan(probe.replace("OLD.object_key", "?"), ("stage-key",)))


if __name__ == '__main__':
    unittest.main()
