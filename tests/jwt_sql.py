"""Check the Rust signing-key SQL against the migrated SQLite schema."""

import sqlite3
import unittest

from sql_source import statement
from sql_regression import apply_migrations


class JwtKeySql(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        self.db.execute("PRAGMA foreign_keys=ON")
        apply_migrations(self.db)
        self.select = statement("jwt_keys", "find")
        self.insert = statement("jwt_keys", "initialize_if_allowed")
        self.wrap = statement("jwt_keys", "wrap_if_current")

    def test_legacy_wrapping_is_an_atomic_compare_and_swap_of_both_fields(self):
        original = (" original-access ", " original-refresh ")
        self.db.execute(self.insert, (*original, 0))
        wrapped = ("v1.first-access", "v1.first-refresh")
        self.assertEqual(self.db.execute(self.wrap, (*wrapped, *original)).rowcount, 1)
        # A competing wrapper of the same plaintext cannot replace the winner.
        self.assertEqual(self.db.execute(self.wrap, ("v1.loser-access", "v1.loser-refresh", *original)).rowcount, 0)
        self.assertEqual(self.db.execute(self.select).fetchone(), wrapped)

    def test_legacy_wrapping_cannot_overwrite_a_change_to_either_field(self):
        for changed in [("changed-access", "original-refresh"), ("original-access", "changed-refresh")]:
            with self.subTest(changed=changed):
                self.db.execute("DELETE FROM jwt_keys")
                self.db.execute(self.insert, (*changed, 0))
                self.assertEqual(self.db.execute(self.wrap, ("v1.access", "v1.refresh", "original-access", "original-refresh")).rowcount, 0)
                self.assertEqual(self.db.execute(self.select).fetchone(), changed)

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
