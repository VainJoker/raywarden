"""Domain settings use the production session, account, settings and cursor SQL."""
import sqlite3
import unittest

from cipher_v2_sql import REVISION
from send_transactions_sql import guard_sql, key_guard, session_sql
from sql_regression import database, statement
from sql_source import literal


class DomainSettingsSql(unittest.TestCase):
    def setUp(self):
        self.db = database()
        self.addCleanup(self.db.close)
        self.db.execute("INSERT INTO devices(user_id,device_id,name,device_type,session_token,created_at,updated_at) VALUES('alice','device','Browser',14,'session','old','old')")
        self.db.execute("UPDATE users SET updated_at='2099-01-01T00:00:00.000Z' WHERE id='alice'")
        self.db.commit()
        self.before = dict(self.db.execute("SELECT * FROM users WHERE id='alice'").fetchone())
        self.settings_guard = guard_sql(literal(
            "domains", "EXISTS(SELECT 1 FROM users WHERE id=?1 AND equivalent_domains=", "snapshot_guard"))

    def state(self):
        return [tuple(row) for row in self.db.execute("SELECT * FROM users ORDER BY id")]

    def commit(self):
        old = self.before
        with self.db:
            self.db.execute(session_sql(), ("alice", "stamp", "device", "session")).fetchall()
            self.db.execute(*key_guard(old)).fetchall()
            self.db.execute(self.settings_guard, ("alice", old["equivalent_domains"], old["excluded_globals"])).fetchall()
            self.db.execute(statement("domains", "update_for_user"), ('[["one.example","two.example"]]', '[1,2]', "alice"))
            return self.db.execute(REVISION, ("2026-11-18T10:00:00.000Z", "alice")).fetchone()[0]

    def test_domain_settings_advance_future_cursor_and_preserve_other_owners(self):
        other = tuple(self.db.execute("SELECT * FROM users WHERE id='bob'").fetchone())
        cursor = self.commit()
        self.assertGreater(cursor, self.before["updated_at"])
        self.assertEqual(tuple(self.db.execute("SELECT equivalent_domains,excluded_globals FROM users WHERE id='alice'").fetchone()), ('[["one.example","two.example"]]', '[1,2]'))
        self.assertEqual(tuple(self.db.execute("SELECT * FROM users WHERE id='bob'").fetchone()), other)

    def test_stale_settings_session_or_account_envelope_fail_without_overwriting_new_state(self):
        for mutation in ("UPDATE users SET equivalent_domains='[[\"concurrent.example\"]]' WHERE id='alice'",
                         "UPDATE users SET key='new-wrapped-key' WHERE id='alice'",
                         "UPDATE devices SET session_token='new-session' WHERE user_id='alice'"):
            self.db.execute(mutation)
            self.db.commit()
            expected = self.state()
            with self.assertRaises(sqlite3.OperationalError):
                self.commit()
            self.assertEqual(self.state(), expected)
            self.db.execute("UPDATE users SET equivalent_domains=?,key=? WHERE id='alice'",
                            (self.before["equivalent_domains"], self.before["key"]))
            self.db.execute("UPDATE devices SET session_token='session' WHERE user_id='alice'")
            self.db.commit()

    def test_late_cursor_failure_rolls_domain_writes_back(self):
        self.db.execute("CREATE TRIGGER domain_failure BEFORE UPDATE OF updated_at ON users BEGIN SELECT RAISE(ABORT,'domain cursor failed'); END")
        expected = self.state()
        with self.assertRaises(sqlite3.IntegrityError):
            self.commit()
        self.assertEqual(self.state(), expected)


if __name__ == "__main__":
    unittest.main(verbosity=2)
