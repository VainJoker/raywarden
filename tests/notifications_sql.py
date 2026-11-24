"""Exercise real push-model SQL and stable relay IDs without Worker bindings."""
import sqlite3
import unittest

from sql_fixtures import apply_migrations
from sql_source import statement


class PushDevices(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.execute("PRAGMA foreign_keys=ON")
        apply_migrations(self.db)
        for user in ("alice", "bob"):
            self.db.execute("INSERT INTO users(id,email,master_password_hash,key,private_key,public_key,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)", (user, f"{user}@test", "hash", "key", "private", "public", "now", "now"))
            self.db.execute("INSERT INTO devices(user_id,device_id,name,device_type,session_token,created_at,updated_at) VALUES(?,?,?,?,?,?,?)", (user, "same-client-id", "phone", 0, f"session-{user}", "now", "now"))

    def tearDown(self):
        self.db.close()

    def test_uuid_assignment_is_stable_and_user_scoped(self):
        ensure = statement("push", "assign_uuid")
        self.assertEqual(self.db.execute(ensure, ("relay-alice", "alice", "same-client-id")).fetchone()[0], "relay-alice")
        self.assertEqual(self.db.execute(ensure, ("replacement", "alice", "same-client-id")).fetchone()[0], "relay-alice")
        self.assertEqual(self.db.execute(ensure, ("relay-bob", "bob", "same-client-id")).fetchone()[0], "relay-bob")
        self.assertIsNone(self.db.execute(ensure, ("intruder", "alice", "other-device")).fetchone())

    def test_push_lookup_and_cleanup_list_cannot_cross_users(self):
        ensure = statement("push", "assign_uuid")
        self.db.execute(ensure, ("relay-alice", "alice", "same-client-id")).fetchall()
        self.db.execute(ensure, ("relay-bob", "bob", "same-client-id")).fetchall()
        self.db.row_factory = sqlite3.Row
        lookup = statement("push", "find_for_user")
        row = self.db.execute(lookup, ("alice", "same-client-id")).fetchone()
        self.assertEqual(row["push_id"], "relay-alice")
        self.assertNotIn("session_token", row.keys())
        listing = statement("push", "list_for_user_statement")
        self.assertEqual([r["push_id"] for r in self.db.execute(listing, ("bob",))], ["relay-bob"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
