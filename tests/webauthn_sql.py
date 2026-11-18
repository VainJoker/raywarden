"""Run the WebAuthn/API-key model SQL against SQLite without Worker bindings."""
import sqlite3
import unittest

from sql_regression import account_snapshot, apply_migrations, statements, statement

NOW = "2026-11-13T03:00:00.000Z"
FUTURE = "2099-01-01T00:00:00.000Z"


class WebAuthnSQL(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        self.db.execute("PRAGMA foreign_keys=ON")
        apply_migrations(self.db, legacy_multi_user=True)
        for user in ("owner", "other"):
            self.db.execute("INSERT INTO users(id,email,master_password_hash,key,private_key,public_key,security_stamp,created_at,updated_at) VALUES(?,?,'hash','key','private','public','stamp',?,?)", (user, user + "@example.com", NOW, NOW))
            self.db.execute("INSERT INTO devices(user_id,identifier,name,type,session_token,created_at,updated_at) VALUES(?,'device','Browser',14,'session',?,?)", (user, NOW, NOW))
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
        self.assertEqual(self.db.execute("SELECT enabled FROM twofactor WHERE user_uuid='owner' AND atype=7").fetchone(),(1,))
        self.assertEqual(self.db.execute("SELECT totp_recover FROM users WHERE id='owner'").fetchone(),("recovery-code",))
        self.assertEqual(self.register()[0],0)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM webauthn_credentials").fetchone(),(1,))

    def test_registration_rejects_session_revoked_after_options(self):
        self.challenge(purpose="register.2fa",session="session")
        self.db.execute("UPDATE devices SET session_token='new-session' WHERE user_id='owner'")
        self.db.commit()
        self.assertEqual(self.register(),[0,0,0,0])
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM webauthn_credentials").fetchone(),(0,))
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM twofactor").fetchone(),(0,))

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

    def test_key_rotation_clears_only_owner_wrapped_prf_material(self):
        self.credential()
        self.db.execute("UPDATE webauthn_credentials SET prf_status=0,encrypted_user_key='old',encrypted_private_key='old',encrypted_public_key='old'")
        self.db.execute(statement("webauthn", "key_rotation_statement"), (NOW, "owner"))
        row = self.db.execute("SELECT prf_status,encrypted_user_key,encrypted_private_key,encrypted_public_key FROM webauthn_credentials").fetchone()
        self.assertEqual(row, (1, None, None, None))

    def test_api_key_binding_rechecks_current_key_and_device_nonce(self):
        self.db.execute("INSERT INTO user_api_keys VALUES('owner','encrypted','keyhash',?)", (NOW,))
        query = statement("api_key", "bind_session")
        self.assertIsNone(self.db.execute(query, ("owner", "device", "session", "old-hash")).fetchone())
        self.assertIsNone(self.db.execute(query, ("owner", "device", "old-session", "keyhash")).fetchone())
        self.assertEqual(self.db.execute(query, ("owner", "device", "session", "keyhash")).fetchone()[0], "owner")

    def test_api_key_rotation_preserves_new_password_session_on_same_device(self):
        self.db.execute("INSERT INTO user_api_keys VALUES('owner','encrypted','oldhash',?)", (NOW,))
        self.db.execute("INSERT INTO user_api_key_sessions VALUES('owner','device','old-api-session')")
        self.db.commit()
        queries = statements("api_key", "replace")
        with self.db:
            self.db.execute(queries[0], ("owner",))
            self.db.execute(queries[1], ("owner",))
            self.db.execute(queries[2], ("owner", "new-encrypted", "newhash", NOW))
            self.db.execute(queries[3], (NOW, "owner"))
        self.assertEqual(self.db.execute("SELECT session_token FROM devices WHERE user_id='owner'").fetchone()[0], "session")
        self.assertIsNotNone(self.db.execute("SELECT 1 FROM devices WHERE user_id='other'").fetchone())


if __name__ == "__main__":
    unittest.main(verbosity=2)
