"""Check TOTP consumption and provider replacement against the actual SQL."""
import json
import re
import sqlite3
import unittest

from sql_regression import NOW, database, statements, statement
from sql_source import source


def clear_recovery_sql():
    query = statement("two_factor", "clear_recovery_statement")
    constants = dict(re.findall(r"const (REMEMBER_PROVIDER|FIRST_INTERNAL_PROVIDER): i32 = (\d+);", source("two_factor")))
    return query.format(**constants)


class TwoFactorAtomicSql(unittest.TestCase):
    def setUp(self):
        self.db = database()
        self.addCleanup(self.db.close)
        self.db.execute("INSERT INTO devices(device_id,user_id,name,device_type,session_token,created_at,updated_at) VALUES('device','alice','test',0,'session','old','old')")
        self.db.execute("INSERT INTO two_factors(id,user_id,provider_type,is_enabled,data,last_used_step) VALUES('factor','alice',0,1,'OLDKEY',1)")

    def test_same_totp_step_can_only_be_consumed_once(self):
        sql = statement('two_factor', 'update_last_used_step')
        self.assertEqual(self.db.execute(sql, (2, 'factor')).rowcount, 1)
        self.assertEqual(self.db.execute(sql, (2, 'factor')).rowcount, 0)
        self.assertEqual(self.db.execute(sql, (1, 'factor')).rowcount, 0)

    def test_replacement_rejects_a_changed_provider_or_revoked_session(self):
        replace, _assert, clear, recovery = statements('two_factor', 'replace_authenticator')
        snapshot = json.dumps({'id': 'factor', 'is_enabled': 1, 'data': 'OLDKEY', 'last_used_step': 1})
        params = ('replacement', 'alice', 1, 'NEWKEY', 2, snapshot, 'stamp', 'device', 'session')
        self.db.execute("UPDATE two_factors SET last_used_step=2 WHERE id='factor'")
        self.assertEqual(self.db.execute(replace, params).rowcount, 0)
        self.db.execute("UPDATE two_factors SET last_used_step=1 WHERE id='factor'")
        self.db.execute("UPDATE devices SET session_token='revoked' WHERE device_id='device'")
        self.assertEqual(self.db.execute(replace, params).rowcount, 0)
        self.db.execute("UPDATE devices SET session_token='session' WHERE device_id='device'")
        self.assertEqual(self.db.execute(replace, params).rowcount, 1)
        self.db.execute(clear, ('alice', 'replacement'))
        self.db.execute(recovery, ('alice', 'new-recovery'))
        self.assertEqual(tuple(self.db.execute("SELECT id,data FROM two_factors WHERE provider_type=0").fetchone()), ('replacement', 'NEWKEY'))
        self.assertEqual(self.recovery(), "new-recovery")
        self.assertEqual(self.db.execute(recovery, ('alice', 'other-recovery')).rowcount, 0)
        self.assertEqual(self.recovery(), "new-recovery")

    def recovery(self):
        return self.db.execute("SELECT two_factor_recovery_code FROM users WHERE id='alice'").fetchone()[0]

    def test_failed_recovery_initialization_rolls_back_authenticator_replacement(self):
        replace, assertion, clear, recovery = statements("two_factor", "replace_authenticator")
        snapshot = json.dumps({"id": "factor", "is_enabled": 1, "data": "OLDKEY", "last_used_step": 1})
        self.db.execute("INSERT INTO two_factors VALUES('remember','alice',5,1,'remember',0)")
        self.db.commit()
        self.db.execute("CREATE TRIGGER reject_recovery BEFORE UPDATE OF two_factor_recovery_code ON users BEGIN SELECT RAISE(ABORT,'recovery write failed'); END")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "recovery write failed"):
            with self.db:
                self.db.execute(replace, ("replacement", "alice", 1, "NEWKEY", 2, snapshot, "stamp", "device", "session"))
                self.db.execute(assertion).fetchone()
                self.db.execute(clear, ("alice", "replacement"))
                self.db.execute(recovery, ("alice", "new-recovery"))
        self.assertEqual([row[0] for row in self.db.execute("SELECT id FROM two_factors ORDER BY id")], ["factor", "remember"])
        self.assertIsNone(self.recovery())

    def test_stale_disable_does_not_remove_a_reconfigured_provider(self):
        delete, _assert, _clear = statements('two_factor', 'delete_authenticator_snapshot')
        self.db.execute("UPDATE two_factors SET data='NEWKEY' WHERE id='factor'")
        self.assertEqual(self.db.execute(delete, ('factor', 'alice', 'OLDKEY', 1, 1, 'stamp', 'device', 'session')).rowcount, 0)
        self.assertEqual(self.db.execute("SELECT data FROM two_factors WHERE id='factor'").fetchone()[0], 'NEWKEY')

    def test_failed_disable_rolls_back_before_remember_tokens_are_removed(self):
        delete, assertion, clear = statements('two_factor', 'delete_authenticator_snapshot')
        self.db.execute("INSERT INTO two_factors(id,user_id,provider_type,is_enabled,data,last_used_step) VALUES('remember','alice',5,1,'remember',0)")
        self.db.execute("DELETE FROM two_factors WHERE id='factor'")
        self.db.commit()
        self.db.execute('BEGIN')
        self.db.execute(delete, ('factor', 'alice', 'OLDKEY', 1, 1, 'stamp', 'device', 'session'))
        with self.assertRaises(sqlite3.OperationalError):
            self.db.execute(assertion)
            self.db.execute(clear, ('alice',))
        self.db.rollback()
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM two_factors WHERE provider_type=5").fetchone()[0], 1)

    def test_modern_disable_keeps_recovery_for_legacy_enabled_provider(self):
        delete, assertion, clear = statements("two_factor", "delete_authenticator_snapshot")
        self.db.execute("UPDATE users SET two_factor_recovery_code='recovery' WHERE id='alice'")
        self.db.execute("INSERT INTO two_factors VALUES('legacy','alice',2,1,'legacy',0)")
        self.db.execute("INSERT INTO two_factors VALUES('internal','alice',1000,1,'internal',0)")
        with self.db:
            self.db.execute(delete, ("factor", "alice", "OLDKEY", 1, 1, "stamp", "device", "session"))
            self.db.execute(assertion).fetchone()
            self.db.execute(clear, ("alice",))
            self.db.execute(clear_recovery_sql(), ("alice", None))
        self.assertEqual(self.recovery(), "recovery")
        self.db.execute("DELETE FROM two_factors WHERE id='legacy'")
        self.db.execute("INSERT INTO two_factors VALUES('remember','alice',5,1,'remember',0)")
        self.db.execute(clear_recovery_sql(), ("alice", "stale-write"))
        self.assertEqual(self.recovery(), "recovery")
        self.db.execute(clear_recovery_sql(), ("alice", None))
        self.assertIsNone(self.recovery())

    def test_generic_provider_disable_rolls_back_auxiliary_cleanup(self):
        invalidate = statement("email", "invalidate_user_statement")
        purge_webauthn = statement("webauthn", "purge_2fa_statement")
        disable = statement("two_factor", "disable_provider")
        self.db.execute("DELETE FROM two_factors")
        self.db.execute("UPDATE users SET two_factor_recovery_code='recovery' WHERE id='alice'")
        self.db.execute("INSERT INTO two_factors VALUES('passkey-factor','alice',7,1,'passkey-factor',0)")
        self.db.execute("INSERT INTO webauthn_credentials(id,user_id,slot,name,credential_id,public_key,sign_count,credential_use,prf_status,created_at,updated_at) VALUES('credential','alice',1,'Key','wire','public',0,'2fa',2,?,?)", (NOW, NOW))
        reserve = statement("email", "reserve_until")
        self.db.execute(reserve, ("code", "alice", "alice", "protected-action", "alice@example.test", "", "hash", "stamp", "session", 100, 700, 40)).fetchone()
        self.db.commit()
        self.db.execute("CREATE TRIGGER reject_recovery BEFORE UPDATE OF two_factor_recovery_code ON users BEGIN SELECT RAISE(ABORT,'recovery write failed'); END")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "recovery write failed"):
            with self.db:
                self.db.execute(invalidate, ("alice",))
                self.db.execute(purge_webauthn, ("alice",))
                self.db.execute(disable, ("alice", 7, 5))
                self.db.execute(clear_recovery_sql(), ("alice", None))
        self.assertEqual(self.db.execute("SELECT id FROM verification_codes").fetchone()[0], "code")
        self.assertEqual(self.db.execute("SELECT id FROM webauthn_credentials").fetchone()[0], "credential")
        self.assertEqual(self.db.execute("SELECT id FROM two_factors").fetchone()[0], "passkey-factor")
        self.assertEqual(self.recovery(), "recovery")


if __name__ == '__main__':
    unittest.main()
