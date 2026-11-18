"""Check TOTP consumption and provider replacement against the actual SQL."""
import json
import sqlite3
import unittest

from sql_regression import database, statements, statement


class TwoFactorAtomicSql(unittest.TestCase):
    def setUp(self):
        self.db = database()
        self.addCleanup(self.db.close)
        self.db.execute("INSERT INTO devices(identifier,user_id,name,type,session_token,created_at,updated_at) VALUES('device','alice','test',0,'session','old','old')")
        self.db.execute("INSERT INTO twofactor(uuid,user_uuid,atype,enabled,data,last_used) VALUES('factor','alice',0,1,'OLDKEY',1)")

    def test_same_totp_step_can_only_be_consumed_once(self):
        sql = statement('twofactor', 'update_last_used')
        self.assertEqual(self.db.execute(sql, (2, 'factor')).rowcount, 1)
        self.assertEqual(self.db.execute(sql, (2, 'factor')).rowcount, 0)
        self.assertEqual(self.db.execute(sql, (1, 'factor')).rowcount, 0)

    def test_replacement_rejects_a_changed_provider_or_revoked_session(self):
        replace, _assert, clear = statements('twofactor', 'replace_authenticator')
        snapshot = json.dumps({'uuid': 'factor', 'enabled': 1, 'data': 'OLDKEY', 'last_used': 1})
        params = ('replacement', 'alice', 1, 'NEWKEY', 2, snapshot, 'stamp', 'device', 'session')
        self.db.execute("UPDATE twofactor SET last_used=2 WHERE uuid='factor'")
        self.assertEqual(self.db.execute(replace, params).rowcount, 0)
        self.db.execute("UPDATE twofactor SET last_used=1 WHERE uuid='factor'")
        self.db.execute("UPDATE devices SET session_token='revoked' WHERE identifier='device'")
        self.assertEqual(self.db.execute(replace, params).rowcount, 0)
        self.db.execute("UPDATE devices SET session_token='session' WHERE identifier='device'")
        self.assertEqual(self.db.execute(replace, params).rowcount, 1)
        self.db.execute(clear, ('alice', 'replacement'))
        self.assertEqual(tuple(self.db.execute("SELECT uuid,data FROM twofactor WHERE atype=0").fetchone()), ('replacement', 'NEWKEY'))

    def test_stale_disable_does_not_remove_a_reconfigured_provider(self):
        delete, _assert, _clear = statements('twofactor', 'delete_authenticator_snapshot')
        self.db.execute("UPDATE twofactor SET data='NEWKEY' WHERE uuid='factor'")
        self.assertEqual(self.db.execute(delete, ('factor', 'alice', 'OLDKEY', 1, 1, 'stamp', 'device', 'session')).rowcount, 0)
        self.assertEqual(self.db.execute("SELECT data FROM twofactor WHERE uuid='factor'").fetchone()[0], 'NEWKEY')

    def test_failed_disable_rolls_back_before_remember_tokens_are_removed(self):
        delete, assertion, clear = statements('twofactor', 'delete_authenticator_snapshot')
        self.db.execute("INSERT INTO twofactor(uuid,user_uuid,atype,enabled,data,last_used) VALUES('remember','alice',5,1,'remember',0)")
        self.db.execute("DELETE FROM twofactor WHERE uuid='factor'")
        self.db.commit()
        self.db.execute('BEGIN')
        self.db.execute(delete, ('factor', 'alice', 'OLDKEY', 1, 1, 'stamp', 'device', 'session'))
        with self.assertRaises(sqlite3.OperationalError):
            self.db.execute(assertion)
            self.db.execute(clear, ('alice',))
        self.db.rollback()
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM twofactor WHERE atype=5").fetchone()[0], 1)


if __name__ == '__main__':
    unittest.main()
