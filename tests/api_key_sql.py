"""Current API-key reads and rotation execute the guarded production SQL."""
import sqlite3
import unittest

from sql_fixtures import NOW, account_snapshot, database
from sql_source import account_guard, statement, statements


def key_snapshot(db, user="alice"):
    cursor = db.execute("SELECT * FROM users WHERE id=?", (user,))
    row = dict(zip((column[0] for column in cursor.description), cursor.fetchone()))
    return (user, row["security_stamp"], row["master_password_hash"], row["password_salt"],
            row["password_iterations"], account_snapshot(db, user), "device", "session")


def replace_key(db, snapshot, previous, marker="api-write", encrypted="new-encrypted", key_hash="new-hash"):
    claim, revoke, clear, replace = statements("api_key", "replace")
    with db:
        changed = db.execute(claim.replace("{}", account_guard(6)), (*snapshot, marker, "2026-11-18T10:00:00.000Z", *(previous or (None, None, None)))).fetchall()
        db.execute(revoke, (snapshot[0], marker))
        db.execute(clear, (snapshot[0], marker))
        db.execute(replace, (snapshot[0], encrypted, key_hash, marker))
    return changed


class ApiKeySql(unittest.TestCase):
    def setUp(self):
        self.db = database()
        self.addCleanup(self.db.close)
        self.db.execute("INSERT INTO devices(user_id,device_id,name,device_type,session_token,created_at,updated_at) VALUES('alice','device','Browser',14,'session','old','old')")
        self.db.execute("INSERT INTO user_api_keys VALUES('alice','old-encrypted','old-hash','old')")
        self.db.commit()
        self.snapshot = key_snapshot(self.db)
        self.previous = ("old-encrypted", "old-hash", "old")

    def state(self):
        return {table: [tuple(row) for row in self.db.execute(f"SELECT * FROM {table} ORDER BY rowid")]
                for table in ("users", "devices", "user_api_keys", "user_api_key_sessions")}

    def start_session(self, key_hash="old-hash"):
        # The account guard has already passed in these binding/rollback cases.
        upsert = statement("device", "persist_session_statement")
        bind, guard = statements("api_key", "start_session")
        with self.db:
            row = self.db.execute(upsert, ("alice", "device", "CLI", 14, "new-session", NOW)).fetchone()
            self.db.execute(bind, ("alice", "device", "new-session", key_hash))
            self.db.execute(guard).fetchone()
        return row

    def test_api_login_rolls_back_device_nonce_if_the_key_rotated(self):
        self.db.execute("UPDATE user_api_keys SET key_hash='rotated' WHERE user_id='alice'")
        self.db.commit()
        before = self.state()
        with self.assertRaisesRegex(sqlite3.OperationalError, "RAY_API_KEY_SESSION_CONFLICT"):
            self.start_session()
        self.assertEqual(self.state(), before)
        self.assertEqual(self.start_session("rotated")["session_token"], "new-session")
        bound = self.db.execute("SELECT device_id,session_token FROM user_api_key_sessions").fetchone()
        self.assertEqual(tuple(bound), ("device", "new-session"))

    def test_failed_binding_leaves_existing_session_and_its_binding_unchanged(self):
        self.db.execute("INSERT INTO user_api_key_sessions VALUES('alice','device','session')")
        self.db.commit()
        self.db.execute("CREATE TRIGGER bind_failure BEFORE INSERT ON user_api_key_sessions BEGIN SELECT RAISE(ABORT, 'injected API key binding failure'); END")
        before = self.state()
        with self.assertRaisesRegex(sqlite3.IntegrityError, "injected API key binding failure"):
            self.start_session()
        self.assertEqual(self.state(), before)

    def test_current_read_is_bound_to_credentials_session_and_account_envelope(self):
        query = statement("api_key", "find_current").replace("{}", account_guard(6))
        self.assertIsNotNone(self.db.execute(query, self.snapshot).fetchone())
        for sql in ("UPDATE users SET master_password_hash='changed' WHERE id='alice'",
                    "UPDATE users SET key='changed-key' WHERE id='alice'",
                    "UPDATE devices SET session_token='changed' WHERE user_id='alice'"):
            self.db.execute("SAVEPOINT changed")
            self.db.execute(sql)
            self.assertIsNone(self.db.execute(query, self.snapshot).fetchone())
            self.db.execute("ROLLBACK TO changed")
            self.db.execute("RELEASE changed")

    def test_stale_credentials_session_or_key_cannot_rotate_or_revoke_devices(self):
        for mutation in ("UPDATE users SET security_stamp='new' WHERE id='alice'",
                         "UPDATE users SET master_password_hash='new' WHERE id='alice'",
                         "UPDATE users SET password_salt='new' WHERE id='alice'",
                         "UPDATE users SET password_iterations=1200000 WHERE id='alice'",
                         "UPDATE users SET key='new' WHERE id='alice'",
                         "UPDATE devices SET session_token='new' WHERE user_id='alice'",
                         "UPDATE user_api_keys SET key_hash='new' WHERE user_id='alice'"):
            with self.subTest(mutation=mutation):
                db = database()
                try:
                    db.execute("INSERT INTO devices(user_id,device_id,name,device_type,session_token,created_at,updated_at) VALUES('alice','device','Browser',14,'session','old','old')")
                    db.execute("INSERT INTO user_api_keys VALUES('alice','old-encrypted','old-hash','old')")
                    snapshot = key_snapshot(db)
                    db.execute(mutation)
                    db.commit()
                    before = {table: [tuple(row) for row in db.execute(f"SELECT * FROM {table} ORDER BY rowid")]
                              for table in ("users", "devices", "user_api_keys", "user_api_key_sessions")}
                    self.assertEqual(replace_key(db, snapshot, self.previous), [])
                    self.assertEqual({table: [tuple(row) for row in db.execute(f"SELECT * FROM {table} ORDER BY rowid")]
                                      for table in before}, before)
                finally:
                    db.close()

    def test_only_one_old_key_snapshot_wins_and_password_session_survives(self):
        self.db.execute("INSERT INTO user_api_key_sessions VALUES('alice','device','old-api-session')")
        self.db.execute("INSERT INTO devices(user_id,device_id,name,device_type,session_token,created_at,updated_at) VALUES('alice','api-device','CLI',14,'api-session','old','old')")
        self.db.execute("INSERT INTO user_api_key_sessions VALUES('alice','api-device','api-session')")
        self.db.execute("INSERT INTO devices(user_id,device_id,name,device_type,session_token,created_at,updated_at) VALUES('bob','device','Browser',14,'bob-session','old','old')")
        self.db.commit()
        self.assertEqual(len(replace_key(self.db, self.snapshot, self.previous)), 1)
        self.assertEqual(replace_key(self.db, self.snapshot, self.previous, marker="loser"), [])
        self.assertEqual(self.db.execute("SELECT session_token FROM devices WHERE user_id='alice' AND device_id='device'").fetchone()[0], "session")
        self.assertEqual(self.db.execute("SELECT session_token FROM devices WHERE user_id='bob' AND device_id='device'").fetchone()[0], "bob-session")
        self.assertIsNone(self.db.execute("SELECT 1 FROM devices WHERE device_id='api-device'").fetchone())
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM user_api_key_sessions").fetchone()[0], 0)

    def test_late_insert_failure_rolls_back_cursor_marker_and_session_revocation(self):
        self.db.execute("INSERT INTO user_api_key_sessions VALUES('alice','device','session')")
        self.db.commit()
        self.db.execute("CREATE TRIGGER api_key_failure BEFORE INSERT ON user_api_keys BEGIN SELECT RAISE(ABORT,'injected API key failure'); END")
        before = self.state()
        with self.assertRaises(sqlite3.IntegrityError):
            replace_key(self.db, self.snapshot, self.previous)
        self.assertEqual(self.state(), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
