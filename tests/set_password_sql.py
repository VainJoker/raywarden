"""Run the actual empty-account initialization transaction against SQLite."""
import sqlite3
import unittest

from account_v2_sql import account_guard
from sql_regression import NOW, OLD, account_snapshot, database, statements


class InitialPasswordSql(unittest.TestCase):
    def setUp(self):
        self.db = database()
        self.addCleanup(self.db.close)
        self.db.execute("UPDATE users SET master_password_hash='',private_key='',public_key='',key='old-wrapper' WHERE id='alice'")
        self.db.execute("INSERT INTO devices(user_id,device_id,name,device_type,session_token,created_at,updated_at) VALUES('alice','device','Browser',14,'nonce',?,?)", (OLD, OLD))
        for user in ("alice", "bob"):
            self.db.execute("INSERT INTO two_factors(id,user_id,provider_type,data) VALUES(?,?,5,'remember')", (user, user))
            self.db.execute("INSERT INTO webauthn_credentials(id,user_id,slot,name,credential_id,public_key,credential_use,prf_status,encrypted_user_key,encrypted_private_key,created_at,updated_at) VALUES(?,?,1,'PRF',?,'public','login',0,'prf-user','prf-private',?,?)", (user, user, user, OLD, OLD))
        self.db.commit()
        self.queries = statements("user", "initialize_password_if_current")
        self.assertEqual(len(self.queries), 4)

    def parameters(self):
        user = self.db.execute("SELECT * FROM users WHERE id='alice'").fetchone()
        return ("new-hash", "new-salt", 600000, "new-wrapper", "2.private", "public", "hint",
                0, 600000, None, None, "random-initialization-marker", NOW, "alice", "stamp",
                user["password_salt"], user["password_iterations"], account_snapshot(self.db, "alice"),
                "device", "nonce", user["kdf_type"], user["kdf_iterations"], user["kdf_memory"], user["kdf_parallelism"])

    def state(self):
        return {table: [tuple(row) for row in self.db.execute(f"SELECT * FROM {table} ORDER BY rowid")]
                for table in ("users", "devices", "two_factors", "webauthn_credentials")}

    def initialize(self, args):
        with self.db:
            changed = self.db.execute(self.queries[0].replace("{}", account_guard(18)), args).fetchone()
            for query in self.queries[1:]:
                self.db.execute(query, (NOW, "alice", args[11]) if query.startswith("UPDATE webauthn_credentials") else ("alice", args[11]))
        return changed

    def test_initialization_rewraps_once_preserves_sessions_and_cleans_only_its_owner(self):
        args = self.parameters()
        bob = dict(self.db.execute("SELECT * FROM users WHERE id='bob'").fetchone())
        self.assertIsNotNone(self.initialize(args))
        user = self.db.execute("SELECT * FROM users WHERE id='alice'").fetchone()
        self.assertEqual((user["key"], user["master_password_hash"], user["password_salt"], user["password_iterations"]), ("new-wrapper", "new-hash", "new-salt", 600000))
        self.assertEqual(user["security_stamp"], "stamp")
        self.assertEqual(self.db.execute("SELECT session_token FROM devices WHERE user_id='alice'").fetchone()[0], "nonce")
        self.assertEqual(self.db.execute("SELECT user_id FROM two_factors").fetchone()[0], "bob")
        alice = self.db.execute("SELECT * FROM webauthn_credentials WHERE user_id='alice'").fetchone()
        self.assertEqual(alice["credential_id"], "alice")
        self.assertEqual(alice["prf_status"], 1)
        self.assertIsNone(alice["encrypted_user_key"])
        self.assertEqual(dict(self.db.execute("SELECT * FROM users WHERE id='bob'").fetchone()), bob)
        self.assertEqual(self.db.execute("SELECT encrypted_user_key FROM webauthn_credentials WHERE user_id='bob'").fetchone()[0], "prf-user")
        complete = self.state()
        self.assertIsNone(self.initialize(args))
        self.assertEqual(self.state(), complete)

    def test_every_initial_state_or_session_change_rejects_the_stale_writer(self):
        for column, value in (("master_password_hash", "concurrent-hash"), ("private_key", "2.concurrent-private"),
                              ("public_key", "other-public"), ("key", "concurrent-wrapper"),
                              ("password_salt", "concurrent-salt"), ("password_iterations", 1200000),
                              ("security_stamp", "concurrent-stamp"), ("security_version", 2),
                              ("user_key_id", "new-id"), ("kdf_type", 1), ("kdf_iterations", 700000),
                              ("kdf_memory", 64), ("kdf_parallelism", 4)):
            with self.subTest(field=column):
                args = self.parameters()
                self.db.execute(f"UPDATE users SET {column}=? WHERE id='alice'", (value,))
                self.db.commit()
                before = self.state()
                self.assertIsNone(self.initialize(args))
                self.assertEqual(self.state(), before)
                # Restore a complete trusted baseline for the next dimension.
                self.reset_owner()
        args = self.parameters()
        self.db.execute("UPDATE devices SET session_token='revoked' WHERE user_id='alice'")
        self.db.commit()
        before = self.state()
        self.assertIsNone(self.initialize(args))
        self.assertEqual(self.state(), before)

    def reset_owner(self):
        self.db.execute("UPDATE users SET master_password_hash='',private_key='',public_key='',key='old-wrapper',password_salt=NULL,password_iterations=100000,security_stamp='stamp',security_version=NULL,user_key_id=NULL,kdf_type=0,kdf_iterations=600000,kdf_memory=NULL,kdf_parallelism=NULL WHERE id='alice'")
        self.db.commit()

    def test_cleanup_failure_rolls_back_verifier_keys_and_remember_together(self):
        self.db.executescript("CREATE TRIGGER reject_init BEFORE UPDATE ON webauthn_credentials BEGIN SELECT RAISE(ABORT,'injected initialization failure'); END;")
        before = self.state()
        with self.assertRaisesRegex(sqlite3.IntegrityError, "injected initialization failure"):
            self.initialize(self.parameters())
        self.assertEqual(self.state(), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
