"""Check the Rust signing-key SQL against the migrated SQLite schema."""

import sqlite3
import unittest

from sql_source import source as read_source
from sql_regression import apply_migrations, rust_strings


class JwtKeySql(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        self.db.execute("PRAGMA foreign_keys=ON")
        apply_migrations(self.db)
        self.sql = [text for text in rust_strings(read_source("jwt_keys"))
                    if text.startswith(("SELECT ", "INSERT "))]
        self.select = next(text for text in self.sql if text.startswith("SELECT "))
        self.insert = next(text for text in self.sql if text.startswith("INSERT "))

    def test_first_insert_wins_and_following_initializers_cannot_replace_keys(self):
        self.assertIsNone(self.db.execute(self.select).fetchone())
        self.assertEqual(self.db.execute(self.insert, ("first-access", "first-refresh", 0)).rowcount, 1)
        self.assertEqual(self.db.execute(self.insert, ("other-access", "other-refresh", 1)).rowcount, 0)
        self.assertEqual(self.db.execute(self.select).fetchone(), ("first-access", "first-refresh"))
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM jwt_keys").fetchone()[0], 1)

    def test_account_deletion_keeps_the_independent_signing_and_wrapping_keys(self):
        self.db.execute(self.insert, ("existing-access", "existing-refresh", 0))
        self.db.execute("INSERT INTO users(id,email,master_password_hash,key,private_key,public_key,created_at,updated_at) VALUES ('owner','owner@example.test','hash','wrapped','private','public','now','now')")
        self.db.execute("DELETE FROM users WHERE id='owner'")
        self.assertEqual(self.db.execute(self.select).fetchone(), ("existing-access", "existing-refresh"))
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("INSERT INTO jwt_keys VALUES ('another', 'access', 'refresh')")
        self.assertEqual(self.db.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_missing_keys_cannot_be_randomly_recreated_for_an_existing_account(self):
        self.db.execute("INSERT INTO users(id,email,master_password_hash,key,private_key,public_key,created_at,updated_at) VALUES ('owner','owner@example.test','hash','wrapped','private','public','now','now')")
        self.assertEqual(self.db.execute(self.insert, ("random-access", "random-refresh", 0)).rowcount, 0)
        self.assertIsNone(self.db.execute(self.select).fetchone())
        # Explicit import preserves the old wrapping key even on a populated DB.
        self.assertEqual(self.db.execute(self.insert, (" original-access ", " original-refresh ", 1)).rowcount, 1)
        self.assertEqual(self.db.execute(self.select).fetchone(), (" original-access ", " original-refresh "))


if __name__ == "__main__":
    unittest.main(verbosity=2)
