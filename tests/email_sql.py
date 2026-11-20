"""Verify actual email/OTP SQL without bindings or outbound delivery.

python3 tests/email_sql.py
"""
import sqlite3
import unittest
from sql_regression import account_snapshot, apply_migrations, statement, statements


class EmailVerification(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA foreign_keys=ON')
        apply_migrations(self.db)
        for user in ('alice', 'bob'):
            self.db.execute("INSERT INTO users(id,email,master_password_hash,key,private_key,public_key,security_stamp,created_at,updated_at) VALUES(?,?,'hash','key','private','public','stamp','old','old')", (user, f'{user}@example.test'))
        self.addCleanup(self.db.close)

    def reserve(self, id='code', user='alice', purpose='protected-action', recipient='alice@example.test', context='', hash='digest', stamp='stamp', session='device-session', now=1000):
        return self.db.execute(statement('email', 'reserve_until'), (id,user,user,purpose,recipient,context,hash,stamp,session,now,now+600,now-60)).fetchone()

    def check(self, hash='digest', consume=True, user='alice', purpose='protected-action', recipient='alice@example.test', context='', stamp='stamp', session='device-session', now=1001):
        return self.db.execute(statement('email','check'), (hash,consume,now,user,purpose,recipient,context,stamp,session,5)).fetchone()

    def ready(self):
        self.reserve()
        self.db.execute(statement('email','mark_ready'), ('code',))

    def test_delivery_must_succeed_before_code_is_valid(self):
        self.reserve()
        self.assertIsNone(self.check())
        self.db.execute(statement('email','cancel'), ('code',))
        self.assertIsNone(self.check())

    def test_every_scope_dimension_is_bound(self):
        self.ready()
        for args in ({'user':'bob'}, {'purpose':'email-login'}, {'recipient':'bob@example.test'}, {'context':'different'}, {'stamp':'new-stamp'}, {'session':'another-device'}):
            self.assertIsNone(self.check(**args))
        self.assertEqual(self.check()['valid'], 1)
        self.assertIsNone(self.check())

    def test_non_consuming_ui_check_then_single_action(self):
        self.ready()
        self.assertEqual(self.check(consume=False)['valid'], 1)
        self.assertEqual(self.check()['valid'], 1)
        self.assertIsNone(self.check())

    def test_wrong_codes_exhaust_budget_and_expiry_is_strict(self):
        self.ready()
        for _ in range(5):
            self.assertEqual(self.check(hash='wrong')['valid'], 0)
        self.assertIsNone(self.check())
        self.reserve(id='fresh', now=1100)
        self.db.execute(statement('email','mark_ready'), ('fresh',))
        self.assertIsNone(self.check(now=1700))

    def test_cooldown_and_replacement_cannot_delete_new_code(self):
        self.assertIsNotNone(self.reserve())
        self.assertIsNone(self.reserve(id='too-soon',now=1059))
        self.assertIsNotNone(self.reserve(id='replacement',now=1060))
        self.db.execute(statement('email','cancel'), ('code',))
        self.assertIsNotNone(self.db.execute("SELECT id FROM verification_codes WHERE id='replacement'").fetchone())

    def test_consumed_or_revoked_code_does_not_suppress_a_new_delivery(self):
        self.ready()
        self.assertEqual(self.check()['valid'], 1)
        self.assertIsNotNone(self.reserve(id='after-consume', now=1002))
        self.assertIsNotNone(self.reserve(id='new-stamp', stamp='rotated', now=1003))
        self.assertIsNotNone(self.reserve(id='new-session', stamp='rotated', session='new-session', now=1004))

    def test_email_change_checks_stamp_and_preserves_other_accounts(self):
        sql = statement('email','change_email')
        self.db.execute("INSERT INTO devices(user_id,device_id,name,device_type,session_token,created_at,updated_at) VALUES('alice','device','Browser',14,'session','old','old')")
        args = ('new@example.test','new-hash','new-salt','rewrapped-key',0,600000,None,None,'new-stamp','new','alice','stamp','hash',account_snapshot(self.db, 'alice'),'device','session',None,600000,600000)
        self.assertEqual(self.db.execute(sql,args).fetchone()['id'],'alice')
        self.assertIsNone(self.db.execute(sql,args).fetchone())
        self.assertEqual(self.db.execute("SELECT email FROM users WHERE id='bob'").fetchone()['email'],'bob@example.test')
        self.assertEqual(self.db.execute("SELECT key FROM users WHERE id='alice'").fetchone()['key'],'rewrapped-key')
        self.assertEqual(self.db.execute("SELECT password_iterations FROM users WHERE id='alice'").fetchone()[0],600000)

    def test_email_claim_cannot_take_another_accounts_address(self):
        sql = statement('email', 'change_email')
        self.db.execute("INSERT INTO devices(user_id,device_id,name,device_type,session_token,created_at,updated_at) VALUES('alice','device','Browser',14,'session','old','old')")
        args = ('BOB@example.test','new-hash','new-salt','rewrapped-key',0,600000,None,None,'new-stamp','new','alice','stamp','hash',account_snapshot(self.db, 'alice'),'device','session',None,600000,600000)
        before = [tuple(row) for row in self.db.execute("SELECT * FROM users ORDER BY id")]
        self.assertIsNone(self.db.execute(sql, args).fetchone())
        self.assertEqual([tuple(row) for row in self.db.execute("SELECT * FROM users ORDER BY id")], before)

    def test_siteverify_token_can_only_be_claimed_once(self):
        sql=statement('email','claim_turnstile')
        self.assertIsNotNone(self.db.execute(sql,('token-hash',1600)).fetchone())
        self.assertIsNone(self.db.execute(sql,('token-hash',1600)).fetchone())

    def test_account_deletion_cascades_codes(self):
        self.ready()
        self.db.execute("DELETE FROM users WHERE id='alice'")
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM verification_codes').fetchone()[0],0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
