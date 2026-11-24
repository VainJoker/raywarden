"""Exercise the production atomic recovery statements with SQLite transactions."""
import sqlite3
import unittest

from sql_fixtures import database
from sql_source import statements


class AtomicTwoFactorRecovery(unittest.TestCase):
    def setUp(self):
        self.db = database()
        self.addCleanup(self.db.close)
        self.sql = statements("two_factor", "recovery_statements")
        self.assertEqual(len(self.sql), 4)
        for owner in ("alice", "bob"):
            self.db.execute("UPDATE users SET two_factor_recovery_code=?,password_salt=NULL,password_iterations=100000,account_write_token='before-recovery' WHERE id=?", (f"Recovery-{owner}", owner))
            for kind in (0, 1, 5):
                self.db.execute("INSERT INTO two_factors(id,user_id,provider_type,is_enabled,data,last_used_step) VALUES(?,?,?,1,'factor-data',0)", (f"{owner}-{kind}", owner, kind))
            self.db.execute("INSERT INTO verification_codes(id,owner_key,user_id,purpose,recipient,code_hash,issued_at,expires_at,ready) VALUES(?,?,?,'email-2fa',?,'hash',1,2,1)", (f"code-{owner}", owner, owner, f"{owner}@example.test"))
            for use in ("login", "2fa"):
                key = f"{owner}-{use}"
                self.db.execute("INSERT INTO webauthn_credentials(id,user_id,slot,name,credential_id,public_key,credential_use,created_at,updated_at) VALUES(?,?,1,'key',?,'public',?,'before','before')", (key, owner, key, use))
        self.db.commit()
        self.snapshot = dict(self.db.execute("SELECT * FROM users WHERE id='alice'").fetchone())

    def state(self):
        return {
            table: [tuple(row) for row in self.db.execute(f"SELECT * FROM {table} ORDER BY rowid")]
            for table in ("users", "two_factors", "verification_codes", "webauthn_credentials")
        }

    def recover(self, snapshot=None, marker="recovery-write"):
        user = self.snapshot if snapshot is None else snapshot
        parameters = (marker, user["id"], user["security_stamp"], user["master_password_hash"], user["password_salt"], user["password_iterations"], user["two_factor_recovery_code"], user["email"])
        with self.db:
            changed = self.db.execute(self.sql[0], parameters).rowcount
            for statement in self.sql[1:]:
                self.db.execute(statement, (user["id"], marker))
        return changed

    def test_recovery_consumes_all_second_factors_but_preserves_login_keys_and_other_users(self):
        before = self.state()
        self.assertEqual(self.recover(), 1)
        user = self.db.execute("SELECT * FROM users WHERE id='alice'").fetchone()
        self.assertIsNone(user["two_factor_recovery_code"])
        for field in ("security_stamp", "master_password_hash", "password_salt", "password_iterations", "updated_at"):
            self.assertEqual(user[field], self.snapshot[field])
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM two_factors WHERE user_id='alice'").fetchone()[0], 0)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM verification_codes WHERE user_id='alice'").fetchone()[0], 0)
        self.assertEqual([row[0] for row in self.db.execute("SELECT credential_use FROM webauthn_credentials WHERE user_id='alice'")], ["login"])
        after = self.state()
        for table, old_rows in before.items():
            owner_column = {"users": 0, "two_factors": 1, "verification_codes": 2, "webauthn_credentials": 1}[table]
            self.assertEqual([row for row in after[table] if row[owner_column] == "bob"], [row for row in old_rows if row[owner_column] == "bob"])

    def test_each_changed_credential_or_code_fences_an_old_verified_snapshot(self):
        for field, changed in (
            ("security_stamp", "new-stamp"), ("master_password_hash", "new-hash"),
            ("password_salt", "new-salt"), ("password_iterations", 600000),
            ("two_factor_recovery_code", "new-recovery"), ("email", "new-alice@example.test"),
        ):
            with self.subTest(field=field):
                self.db.execute(f"UPDATE users SET {field}=? WHERE id='alice'", (changed,))
                self.db.commit()
                before = self.state()
                self.assertEqual(self.recover(marker=f"stale-{field}"), 0)
                self.assertEqual(self.state(), before)
                self.db.execute(f"UPDATE users SET {field}=? WHERE id='alice'", (self.snapshot[field],))
                self.db.commit()

    def test_replay_and_absent_code_do_not_change_the_completed_state(self):
        self.assertEqual(self.recover(), 1)
        completed = self.state()
        self.assertEqual(self.recover(marker="replay-write"), 0)
        self.assertEqual(self.state(), completed)
        current = dict(self.db.execute("SELECT * FROM users WHERE id='alice'").fetchone())
        self.assertEqual(self.recover(current, marker="missing-code"), 0)
        self.assertEqual(self.state(), completed)

    def test_error_after_credential_and_code_cleanup_rolls_the_entire_batch_back(self):
        self.db.executescript("CREATE TRIGGER reject_recovery BEFORE DELETE ON two_factors WHEN OLD.user_id='alice' BEGIN SELECT RAISE(ABORT, 'injected recovery failure'); END;")
        before = self.state()
        with self.assertRaisesRegex(sqlite3.IntegrityError, "injected recovery failure"):
            self.recover()
        self.assertEqual(self.state(), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
