"""Run the WebAuthn/API-key model SQL against SQLite without Worker bindings."""
import json
import sqlite3
import unittest

from sql_regression import account_snapshot, apply_migrations, statements, statement
from sql_source import literal

NOW = "2026-11-13T03:00:00.000Z"
FUTURE = "2099-01-01T00:00:00.000Z"


class WebAuthnSQL(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        self.db.execute("PRAGMA foreign_keys=ON")
        apply_migrations(self.db)
        for user in ("owner", "other"):
            self.db.execute("INSERT INTO users(id,email,master_password_hash,key,private_key,public_key,security_stamp,created_at,updated_at) VALUES(?,?,'hash','key','private','public','stamp',?,?)", (user, user + "@example.com", NOW, NOW))
            self.db.execute("INSERT INTO devices(user_id,device_id,name,device_type,session_token,created_at,updated_at) VALUES(?,'device','Browser',14,'session',?,?)", (user, NOW, NOW))
        self.db.commit()

    def challenge(self, user="owner", purpose="assert.2fa", session=None):
        self.db.execute(statement("webauthn", "insert"),
                        ("challenge-id", "random-challenge", purpose, user, "stamp" if user else None,
                         "device", session, "vault.example", "https://vault.example", FUTURE,
                         account_snapshot(self.db, user) if user else None))
        self.db.commit()

    def credential(self, count=0):
        self.db.execute("INSERT INTO webauthn_credentials(id,user_id,slot,name,credential_id,public_key,sign_count,credential_use,created_at,updated_at) VALUES('credential','owner',1,'Key','credential-wire-id','public-key',?,'2fa',?,?)", (count, NOW, NOW))
        self.db.commit()

    def assertion(self, old, new, user="owner"):
        queries = statements("webauthn", "accept_assertion")
        with self.db:
            first = self.db.execute(queries[0], (new, "challenge-id", NOW, "credential", old, user)).rowcount
            second = self.db.execute(queries[1], (NOW, "challenge-id", "credential")).rowcount
        return first, second

    def register(self):
        queries=statements("webauthn","register")
        args=[("new-credential","owner",1,"Key","wire-id","public",0,"2fa",2,None,None,None,"challenge-id",NOW,account_snapshot(self.db, "owner")),
              (NOW,"challenge-id","new-credential"),
              ("factor-id","owner","2fa","new-credential","challenge-id"),
              (NOW,"owner","2fa","recovery-code","new-credential","challenge-id")]
        with self.db:
            return [self.db.execute(query,params).rowcount for query,params in zip(queries,args)]

    def test_registration_atomically_enables_factor_and_issues_recovery_code(self):
        self.challenge(purpose="register.2fa",session="session")
        self.assertEqual(self.register(),[1,1,1,1])
        self.assertEqual(self.db.execute("SELECT is_enabled FROM two_factors WHERE user_id='owner' AND provider_type=7").fetchone(),(1,))
        self.assertEqual(self.db.execute("SELECT two_factor_recovery_code FROM users WHERE id='owner'").fetchone(),("recovery-code",))
        self.assertEqual(self.register()[0],0)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM webauthn_credentials").fetchone(),(1,))

    def test_registration_rejects_session_revoked_after_options(self):
        self.challenge(purpose="register.2fa",session="session")
        self.db.execute("UPDATE devices SET session_token='new-session' WHERE user_id='owner'")
        self.db.commit()
        self.assertEqual(self.register(),[0,0,0,0])
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM webauthn_credentials").fetchone(),(0,))
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM two_factors").fetchone(),(0,))

    def test_zero_counter_assertion_challenge_is_consumed_once(self):
        self.credential()
        self.challenge()
        self.assertEqual(self.assertion(0, 0), (1, 1))
        self.assertEqual(self.assertion(0, 0), (0, 0))

    def test_stamp_owner_and_counter_mismatches_cannot_consume_challenge(self):
        for kind in ("stamp", "owner", "counter"):
            with self.subTest(kind=kind):
                self.setUp()
                self.credential(5)
                self.challenge(user="other" if kind == "owner" else "owner")
                if kind == "stamp":
                    self.db.execute("UPDATE users SET security_stamp='new' WHERE id='owner'")
                    self.db.commit()
                old = 4 if kind == "counter" else 5
                self.assertEqual(self.assertion(old, 6), (0, 0))
                self.assertIsNone(self.db.execute("SELECT consumed_at FROM webauthn_challenges").fetchone()[0])

    def test_authenticated_assertion_rechecks_device_session(self):
        self.credential()
        self.challenge(purpose="assert.login", session="session")
        self.db.execute("UPDATE devices SET session_token='new-session' WHERE user_id='owner'")
        self.db.commit()
        self.assertEqual(self.assertion(0, 1), (0, 0))

    def test_purpose_and_expiry_lookup_is_strict(self):
        self.challenge()
        query = statement("webauthn", "find_challenge")
        self.assertIsNotNone(self.db.execute(query, ("random-challenge", "assert.2fa", NOW)).fetchone())
        self.assertIsNone(self.db.execute(query, ("random-challenge", "register.2fa", NOW)).fetchone())
        self.assertIsNone(self.db.execute(query, ("random-challenge", "assert.2fa", "2100-01-01T00:00:00.000Z")).fetchone())

    def test_key_rotation_rewraps_only_the_claimed_owner_passkey(self):
        self.credential()
        self.db.execute("INSERT INTO webauthn_credentials(id,user_id,slot,name,credential_id,public_key,credential_use,created_at,updated_at) VALUES('other-key','other',1,'Key','other-wire','public','login',?,?)", (NOW, NOW))
        self.db.execute("UPDATE webauthn_credentials SET prf_status=0,encrypted_user_key='old',encrypted_private_key='private',encrypted_public_key='old'")
        query = literal("account_rotation", "UPDATE webauthn_credentials SET ", "passkey_write")
        snapshot = account_snapshot(self.db, "owner")
        args = ("new-public", "new-user-key", NOW, "owner", "1", "claimed", snapshot)
        self.assertEqual(self.db.execute(query, args).rowcount, 0)
        self.db.execute("UPDATE users SET account_write_token='claimed' WHERE id='owner'")
        self.assertEqual(self.db.execute(query, args).rowcount, 1)
        row = self.db.execute("SELECT encrypted_public_key,encrypted_user_key,encrypted_private_key,account_snapshot FROM webauthn_credentials WHERE id='credential'").fetchone()
        self.assertEqual(row[:3], ("new-public", "new-user-key", "private"))
        self.assertEqual(json.loads(row[3]), json.loads(snapshot))
        self.assertEqual(self.db.execute("SELECT encrypted_user_key FROM webauthn_credentials WHERE id='other-key'").fetchone()[0], "old")

    def test_changed_private_key_invalidates_only_claimed_owner_prf(self):
        self.credential()
        self.db.execute("INSERT INTO webauthn_credentials(id,user_id,slot,name,credential_id,public_key,credential_use,created_at,updated_at) VALUES('other-key','other',1,'Key','other-wire','public','login',?,?)", (NOW, NOW))
        self.db.execute("UPDATE webauthn_credentials SET prf_status=0,encrypted_user_key='old',encrypted_private_key='private',encrypted_public_key='old',account_snapshot='snapshot'")
        query = next(
            sql for sql in statements("account_rotation", "change_credentials")
            if sql.startswith("UPDATE webauthn_credentials SET ") and "encrypted_public_key=NULL" in sql)
        self.assertEqual(self.db.execute(query, (NOW, "owner", "claimed")).rowcount, 0)
        self.db.execute("UPDATE users SET account_write_token='claimed' WHERE id='owner'")
        self.assertEqual(self.db.execute(query, (NOW, "owner", "claimed")).rowcount, 1)
        row = self.db.execute("SELECT prf_status,encrypted_user_key,encrypted_private_key,encrypted_public_key,account_snapshot FROM webauthn_credentials WHERE id='credential'").fetchone()
        self.assertEqual(row, (1, None, None, None, None))
        self.assertEqual(self.db.execute("SELECT encrypted_user_key FROM webauthn_credentials WHERE id='other-key'").fetchone()[0], "old")

    def prf_update(self):
        self.credential(1)
        self.challenge(purpose="assert.login", session="session")
        self.db.execute("UPDATE webauthn_credentials SET credential_use='login',last_challenge='challenge-id'")
        self.db.execute("UPDATE webauthn_challenges SET consumed_at=?", (NOW,))
        self.db.commit()
        return statement("webauthn", "update_keys"), ("Key", 0, "new-public", "new-user", "new-private", NOW,
            "credential", "owner", account_snapshot(self.db, "owner"), "stamp", "device", "session", 1, "challenge-id")

    def test_prf_update_requires_the_accepted_proof_and_current_live_session(self):
        query, args = self.prf_update()
        self.assertIsNotNone(self.db.execute(query, args).fetchone())
        self.assertEqual(self.db.execute("SELECT encrypted_public_key,encrypted_user_key,encrypted_private_key FROM webauthn_credentials").fetchone(),
                         ("new-public", "new-user", "new-private"))

    def test_prf_final_write_rejects_revocation_and_a_newer_assertion_after_verification(self):
        query, args = self.prf_update()
        for mutation in (
            "UPDATE devices SET session_token='revoked' WHERE user_id='owner'",
            "UPDATE users SET security_stamp='revoked' WHERE id='owner'",
            "UPDATE users SET private_key='concurrent-private' WHERE id='owner'",
            "UPDATE webauthn_credentials SET sign_count=2",
            "UPDATE webauthn_credentials SET last_challenge='new-assertion'",
            "UPDATE webauthn_challenges SET consumed_at=NULL",
            "UPDATE webauthn_challenges SET purpose='assert.2fa'",
        ):
            with self.subTest(mutation=mutation):
                self.db.execute(mutation)
                self.assertIsNone(self.db.execute(query, args).fetchone())
                self.assertIsNone(self.db.execute("SELECT encrypted_user_key FROM webauthn_credentials").fetchone()[0])
                self.db.rollback()

    def test_api_key_rotation_preserves_new_password_session_on_same_device(self):
        self.db.execute("INSERT INTO user_api_keys VALUES('owner','encrypted','oldhash',?)", (NOW,))
        self.db.execute("INSERT INTO user_api_key_sessions VALUES('owner','device','old-api-session')")
        self.db.commit()
        from api_key_sql import key_snapshot, replace_key
        self.assertEqual(len(replace_key(self.db, key_snapshot(self.db, "owner"),
                                        ("encrypted", "oldhash", NOW),
                                        encrypted="new-encrypted", key_hash="newhash")), 1)
        self.assertEqual(self.db.execute("SELECT session_token FROM devices WHERE user_id='owner'").fetchone()[0], "session")
        self.assertIsNotNone(self.db.execute("SELECT 1 FROM devices WHERE user_id='other'").fetchone())


if __name__ == "__main__":
    unittest.main(verbosity=2)
