"""Run deletion triggers and the Rust outbox SQL against real SQLite."""
import json
import sqlite3
import unittest

from sql_source import source as read_source
from sql_regression import apply_migrations, rust_strings


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
        sql = list(rust_strings(read_source("storage_cleanup")))
        self.enqueue = next(v for v in sql if v.startswith("INSERT INTO storage_cleanup_jobs"))
        self.select = next(v for v in sql if v.startswith("SELECT object_key, generation"))
        self.ack = next(v for v in sql if v.startswith("DELETE FROM storage_cleanup_jobs"))

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


if __name__ == '__main__':
    unittest.main()
