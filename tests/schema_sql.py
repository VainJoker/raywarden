"""Database invariants exercised directly against the D1 migrations."""

import sqlite3
import unittest
from pathlib import Path

from scripts.schema import generate_schema

ROOT = Path(__file__).resolve().parents[1]
DATE = "2026-01-01T00:00:00.000Z"


class SchemaSql(unittest.TestCase):
    def setUp(self):
        self.db = self.open_database()
        for path in sorted((ROOT / "sql/migrations").glob("*.sql")):
            self.db.executescript(path.read_text())

    def open_database(self):
        db = sqlite3.connect(":memory:")
        self.addCleanup(db.close)
        db.execute("PRAGMA foreign_keys=ON")
        return db

    def insert_user(self, user, email=None):
        self.db.execute("""
            INSERT INTO users(id,email,master_password_hash,key,private_key,public_key,created_at,updated_at)
            VALUES(?,?,'hash','key','private','public',?,?)
        """, (user, email or f"{user}@example.test", DATE, DATE))

    def insert_cipher(self, cipher, user, folder=None):
        self.db.execute("""
            INSERT INTO ciphers(id,user_id,cipher_type,data,folder_id,created_at,updated_at)
            VALUES(?,?,1,'{}',?,?,?)
        """, (cipher, user, folder, DATE, DATE))

    def insert_attachment(self, cipher, storage_key):
        self.db.execute("""
            INSERT INTO attachments(id,cipher_id,file_name,file_size_bytes,encrypted_key,storage_key,created_at,updated_at)
            VALUES(?,?,'encrypted',12,'file-key',?,?,?)
        """, (cipher, cipher, storage_key, DATE, DATE))

    def test_schema_snapshot_matches_migrations_without_data_or_history(self):
        snapshot = self.open_database()
        snapshot.executescript(generate_schema())
        objects = """
            SELECT type, name, tbl_name, sql FROM sqlite_schema
            WHERE name NOT GLOB 'sqlite_*'
            ORDER BY type, name
        """
        self.assertEqual(snapshot.execute(objects).fetchall(), self.db.execute(objects).fetchall())
        for db in (self.db, snapshot):
            tables = db.execute("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT GLOB 'sqlite_*'")
            for (table,) in tables:
                self.assertNotEqual(table, "d1_migrations")
                quoted = table.replace('"', '""')
                self.assertEqual(db.execute(f'SELECT COUNT(*) FROM "{quoted}"').fetchone()[0], 0, table)

    def test_account_emails_are_unique_ignoring_case(self):
        self.insert_user("alice")
        with self.assertRaises(sqlite3.IntegrityError):
            self.insert_user("duplicate", "ALICE@example.test")

    def test_folder_ownership_is_enforced_on_insert_update_and_owner_change(self):
        self.insert_user("alice")
        self.insert_user("bob")
        self.db.execute("INSERT INTO folders VALUES('folder','alice','encrypted',?,?)", (DATE, DATE))
        self.insert_cipher("alice-cipher", "alice", "folder")
        self.insert_cipher("bob-cipher", "bob")
        with self.assertRaises(sqlite3.IntegrityError):
            self.insert_cipher("foreign", "bob", "folder")
        for statement in (
            "UPDATE ciphers SET user_id='bob' WHERE id='alice-cipher'",
            "UPDATE ciphers SET folder_id='folder' WHERE id='bob-cipher'",
            "UPDATE folders SET user_id='bob' WHERE id='folder'",
        ):
            with self.subTest(statement=statement), self.assertRaises(sqlite3.IntegrityError):
                self.db.execute(statement)
        self.db.execute("DELETE FROM folders WHERE id='folder'")
        self.assertEqual(self.db.execute("SELECT folder_id FROM ciphers WHERE id='alice-cipher'").fetchone(), (None,))

    def test_api_sessions_must_belong_to_the_device_owner_and_are_deleted_with_it(self):
        self.insert_user("alice")
        self.insert_user("bob")
        self.db.execute("""
            INSERT INTO devices(user_id,device_id,name,device_type,session_token,created_at,updated_at)
            VALUES('alice','device','Browser',14,'session',?,?)
        """, (DATE, DATE))
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("INSERT INTO user_api_key_sessions VALUES('bob','device','session')")
        self.db.execute("INSERT INTO user_api_key_sessions VALUES('alice','device','session')")
        self.db.execute("DELETE FROM devices WHERE user_id='alice' AND device_id='device'")
        self.assertEqual(self.db.execute("SELECT * FROM user_api_key_sessions").fetchall(), [])

    def test_replacing_and_deleting_files_only_enqueues_superseded_objects(self):
        for user in ("alice", "bob"):
            self.insert_user(user)
            self.insert_cipher(user, user)
            self.insert_attachment(user, f"{user}-old")
        self.db.execute("""
            INSERT INTO attachments_pending(id,cipher_id,file_name,file_size_bytes,encrypted_key,created_at,updated_at)
            VALUES('pending','alice','encrypted',12,'file-key',?,?)
        """, (DATE, DATE))
        self.db.execute("""
            INSERT INTO sends(id,user_id,name,send_type,data,encrypted_key,access_stamp,created_at,updated_at,deletes_at,file_id,upload_state,storage_key)
            VALUES('send','alice','encrypted',1,'{}','send-key','stamp',?,?,?,'file',2,'send-old')
        """, (DATE, DATE, DATE))

        def cleanup_keys():
            return {key for (key,) in self.db.execute("SELECT object_key FROM storage_cleanup_jobs")}

        self.db.execute("UPDATE attachments SET storage_key='alice-new' WHERE id='alice'")
        self.db.execute("UPDATE sends SET storage_key='send-new' WHERE id='send'")
        self.assertEqual(cleanup_keys(), {"alice-old", "send-old"})
        self.db.execute("DELETE FROM users WHERE id='alice'")
        self.assertEqual(cleanup_keys(), {"alice-old", "alice-new", "send-old", "send-new", "alice/pending"})
        self.assertEqual(self.db.execute("SELECT id FROM ciphers").fetchall(), [("bob",)])
        self.assertEqual(self.db.execute("SELECT storage_key FROM attachments").fetchall(), [("bob-old",)])
        self.assertEqual(self.db.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_invalid_file_vault_and_factor_states_are_rejected(self):
        self.insert_user("alice")
        self.insert_cipher("cipher", "alice")
        self.insert_attachment("cipher", "object")
        self.db.execute("""
            INSERT INTO sends(id,user_id,name,send_type,data,encrypted_key,access_stamp,created_at,updated_at,deletes_at)
            VALUES('send','alice','encrypted',0,'{}','send-key','stamp',?,?,?)
        """, (DATE, DATE, DATE))
        self.db.execute("INSERT INTO two_factors(id,user_id,provider_type,data) VALUES('totp','alice',0,'secret')")
        for statement in (
            "UPDATE sends SET upload_state=3",
            "UPDATE attachments SET file_size_bytes=-1",
            "UPDATE ciphers SET cipher_type=9",
            "INSERT INTO two_factors(id,user_id,provider_type,data) VALUES('duplicate','alice',0,'secret')",
        ):
            with self.subTest(statement=statement), self.assertRaises(sqlite3.IntegrityError):
                self.db.execute(statement)

    def test_server_password_cost_accepts_only_positive_u32_independent_of_client_kdf(self):
        self.insert_user("alice")
        for value in (None, 0, -1, 4294967296, 100000.5, "invalid"):
            with self.subTest(cost=value), self.assertRaises(sqlite3.IntegrityError):
                self.db.execute("UPDATE users SET password_iterations=?", (value,))
        for value in (1, 4294967295):
            with self.subTest(cost=value):
                self.db.execute("UPDATE users SET password_iterations=?,kdf_type=1,kdf_iterations=3", (value,))
                self.assertEqual(self.db.execute("SELECT password_iterations,kdf_iterations FROM users").fetchone(), (value, 3))
