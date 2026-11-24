"""Run account-envelope and approval generation guards against SQLite."""
import json
import re
import sqlite3
import unittest

from sql_fixtures import NOW, OLD, FUTURE, account_snapshot, database, seed_attachment, seed_cipher, send_guard
from sql_source import account_guard, literal, rust_strings, source as read_source, statement, statements


def service_strings():
    return list(rust_strings(read_source("account_rotation")))


def rotation_claim(db, user="alice"):
    """Interpolate the real claim and per-row guard SQL without a collection blob."""
    source = read_source("account_rotation")
    constants = {}
    for name in ("CIPHERS", "FOLDERS", "ATTACHMENTS", "PASSKEYS"):
        match = re.search(rf"const {name}:.*?=\s*&\[(.*?)\];", source, re.S)
        constants[name] = list(rust_strings(match.group(1)))
    guard_template = statement("cipher_mutation", "guard")
    def guard(predicate, values):
        return guard_template.format(predicate=predicate), values
    guards = []
    for table, name, where in [
        ("ciphers", "CIPHERS", "user_id=?1"), ("folders", "FOLDERS", "user_id=?1"),
        ("attachments", "ATTACHMENTS", "cipher_id IN (SELECT id FROM ciphers WHERE user_id=?1)"),
        ("webauthn_credentials", "PASSKEYS", "user_id=?1"),
    ]:
        columns = constants[name]
        rows = db.execute(f"SELECT {','.join(columns)} FROM {table} WHERE {where} ORDER BY id", (user,)).fetchall()
        guards.append(guard(f"(SELECT COUNT(*) FROM {table} WHERE {where})=?2", (user, len(rows))))
        predicate = " AND ".join(f"{column} IS ?{i+2}" for i, column in enumerate(columns))
        for row in rows:
            guards.append(guard(f"EXISTS(SELECT 1 FROM {table} WHERE {where} AND {predicate})", (user, *row)))
    sends = db.execute("SELECT * FROM sends WHERE user_id=? ORDER BY id", (user,)).fetchall()
    guards.append(guard(literal("send_mutation", "(SELECT COUNT(*) FROM sends"), (user, len(sends))))
    guards.extend(send_guard(dict(row)) for row in sends)
    claim = statement("account_rotation", "claim_rotation").replace("{}", account_guard(23))
    old = dict(db.execute("SELECT * FROM users WHERE id=?", (user,)).fetchone())
    args = ["new-user-key", "7.new-private", "public", "signed", "state", 2,
            '{"signatureAlgorithm":"ed25519","wrappedSigningKey":"7.signing","verifyingKey":"verify"}',
            "a" * 32, '{"wrappedUserKey1":"one","wrappedUserKey2":"two"}', old["security_stamp"],
            "fresh-random-write-token", old["master_password_hash"], old["password_salt"], old["kdf_type"],
            old["kdf_iterations"], old["kdf_memory"], old["kdf_parallelism"], old["master_password_hint"],
            NOW, user, old["security_stamp"], old["master_password_hash"], account_snapshot(db, user), "device", "nonce",
            old["password_salt"], old["password_iterations"], old["password_iterations"]]
    return claim, args, guards


def apply_rotation(db, claim, args, guards):
    with db:
        changed = db.execute(claim, args).fetchone()
        for query, values in guards:
            db.execute(query, values).fetchall()
    return changed


class AccountV2Sql(unittest.TestCase):
    def setUp(self):
        self.db = database()
        self.addCleanup(self.db.close)
        self.db.execute("INSERT INTO devices(user_id,device_id,name,device_type,session_token,created_at,updated_at) VALUES('alice','device','Browser',14,'nonce',?,?)", (OLD, OLD))
        seed_cipher(self.db, "cipher", data='{"name":"encrypted"}')
        self.db.commit()

    def approval(self):
        self.db.execute(statement("auth_request", "insert"),
                        ("approval", "alice", "request-device", 2, "ip", "code", "public", "stamp", NOW, FUTURE, account_snapshot(self.db, "alice")))
        self.db.commit()

    def test_same_stamp_account_upgrade_invalidates_pending_approval(self):
        self.approval()
        self.db.execute("UPDATE users SET key='new-key',security_version=2 WHERE id='alice'")
        row = self.db.execute(statement("auth_request", "respond"),
                              (1, "wrapped", None, NOW, "device", "approval", "alice", "stamp", "nonce")).fetchone()
        self.assertIsNone(row)
        self.assertIsNone(self.db.execute("SELECT approved FROM auth_requests").fetchone()[0])

    def test_same_stamp_upgrade_invalidates_approved_exchange(self):
        self.approval()
        self.assertIsNotNone(self.db.execute(statement("auth_request", "respond"),
                                            (1, "wrapped", None, NOW, "device", "approval", "alice", "stamp", "nonce")).fetchone())
        self.db.execute("UPDATE users SET private_key='7.new-private' WHERE id='alice'")
        self.assertIsNone(self.db.execute(statement("auth_request", "consume"), (NOW, "approval")).fetchone())

    def test_rotation_claim_uses_exact_account_and_vault_rows(self):
        claim, args, guards = rotation_claim(self.db)
        self.db.execute("UPDATE ciphers SET data='concurrent-cipher' WHERE id='cipher'")
        self.db.commit()
        with self.assertRaises(sqlite3.OperationalError):
            apply_rotation(self.db, claim, args, guards)
        child = next(s for s in service_strings() if s.startswith("UPDATE ciphers SET data="))
        self.assertEqual(self.db.execute(child, ("stale-rotation", NOW, "cipher", "alice", "fresh-random-write-token")).rowcount, 0)
        self.assertEqual(self.db.execute("SELECT key FROM users WHERE id='alice'").fetchone()[0], "key")
        self.assertEqual(self.db.execute("SELECT data FROM ciphers WHERE id='cipher'").fetchone()[0], "concurrent-cipher")

    def test_rotation_commits_once_and_rejects_snapshot_replay(self):
        claim, args, guards = rotation_claim(self.db)
        self.assertIsNotNone(apply_rotation(self.db, claim, args, guards))
        self.assertIsNone(apply_rotation(self.db, claim, args, guards))
        user = self.db.execute("SELECT key,user_key_id,security_stamp FROM users WHERE id='alice'").fetchone()
        self.assertEqual(tuple(user), ("new-user-key", "a" * 32, "stamp"))

    def test_key_only_rotation_preserves_the_existing_verifier_cost(self):
        self.db.execute("UPDATE users SET password_salt='old-salt',password_iterations=1200000 WHERE id='alice'")
        self.db.commit()
        claim, args, guards = rotation_claim(self.db)
        self.assertIsNotNone(apply_rotation(self.db, claim, args, guards))
        self.assertEqual(tuple(self.db.execute("SELECT master_password_hash,password_salt,password_iterations FROM users WHERE id='alice'").fetchone()),
                         ("hash", "old-salt", 1200000))

    def test_pending_attachment_blocks_rotation_inside_the_claim(self):
        claim, args, guards = rotation_claim(self.db)
        seed_attachment(self.db, "pending", "cipher", pending=True, name="file", key="old-key")
        self.db.commit()
        self.assertIsNone(apply_rotation(self.db, claim, args, guards))

    def test_large_blob_collection_stays_under_d1_value_and_function_limits(self):
        self.db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 2_000_000)
        self.db.setlimit(sqlite3.SQLITE_LIMIT_FUNCTION_ARG, 32)
        self.db.execute("DELETE FROM ciphers")
        for number in range(5):
            self.db.execute("INSERT INTO ciphers(id,user_id,cipher_type,data,created_at,updated_at) VALUES(?,'alice',1,?,?,?)", (f"large-{number}", "x" * 450_000, OLD, OLD))
        self.db.commit()
        claim, args, guards = rotation_claim(self.db)
        self.assertLess(max(len(value.encode()) for _, values in guards for value in values if isinstance(value, str)), 500_000)
        self.assertIsNotNone(apply_rotation(self.db, claim, args, guards))
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM ciphers").fetchone()[0], 5)

    def test_rotation_attachment_writes_require_matching_cipher_and_write_token(self):
        seed_cipher(self.db, "a", data={"name": "encrypted", "key": "wrapped-item-key"})
        seed_cipher(self.db, "b", "bob")
        seed_attachment(self.db, "file-a", "a")
        seed_attachment(self.db, "file-b", "b")
        self.db.execute(statement("device", "persist_session_statement"), ("alice", "device", "browser", 2, "nonce", NOW))
        claim, args, guards = rotation_claim(self.db)
        cipher_update = literal("account_rotation", "UPDATE ciphers SET data=", "cipher_write")
        attachment_update = literal("account_rotation", "UPDATE attachments SET ", "attachment_write")
        self.db.commit()
        with self.db:
            self.assertIsNotNone(self.db.execute(claim, args).fetchone())
            for query, values in guards:
                self.db.execute(query, values).fetchall()
            self.assertEqual(self.db.execute(cipher_update, ('{"name":"rotated","key":"rotated-key"}', NOW, "a", "alice", args[10])).rowcount, 1)
            self.assertEqual(self.db.execute(attachment_update, ("rotated-file", "rotated-file-key", NOW, "file-a", "a", "alice", args[10])).rowcount, 1)
            self.db.execute(attachment_update, ("bad-file", "bad-key", NOW, "file-b", "a", "alice", args[10]))
            self.db.execute(attachment_update, ("bad-file", "bad-key", NOW, "file-b", "b", "alice", "wrong-write-token"))
        rows = {row["id"]: row["encrypted_key"] for row in self.db.execute("SELECT * FROM attachments")}
        self.assertEqual(rows, {"file-a": "rotated-file-key", "file-b": "attachment-key"})
        value = self.db.execute("SELECT * FROM ciphers WHERE id=?", ("a",)).fetchone()
        self.assertEqual(json.loads(value["data"])["key"], "rotated-key")

    def test_failed_rotation_rolls_back_content_and_wrapping_keys_together(self):
        seed_cipher(self.db, "a", data={"name": "encrypted", "key": "wrapped-item-key"})
        seed_attachment(self.db, "file-a", "a")
        self.db.execute(
            "INSERT INTO sends(id,user_id,name,send_type,data,encrypted_key,created_at,updated_at,deletes_at,access_stamp) "
            "VALUES('send','alice','encrypted-name',0,'{}','wrapped-send-key',?,?,?,'access-stamp')",
            (NOW, NOW, FUTURE),
        )
        self.approval()
        self.db.execute(statement("device", "persist_session_statement"), ("alice", "device", "browser", 2, "nonce", NOW))
        # Inject a late failure at the real rotation batch's approval cleanup.
        self.db.execute("CREATE TEMP TRIGGER reject_rotation_cleanup BEFORE DELETE ON auth_requests BEGIN SELECT RAISE(ABORT,'injected cleanup failure'); END")
        claim, args, guards = rotation_claim(self.db)
        cipher_update = literal("account_rotation", "UPDATE ciphers SET data=", "cipher_write")
        attachment_update = literal("account_rotation", "UPDATE attachments SET ", "attachment_write")
        cleanup = literal("account_rotation", "DELETE FROM auth_requests WHERE user_id=?1 AND EXISTS", "invalidation_writes")
        self.db.commit()
        with self.assertRaisesRegex(sqlite3.IntegrityError, "injected cleanup failure"):
            with self.db:
                self.assertIsNotNone(self.db.execute(claim, args).fetchone())
                for query, values in guards:
                    self.db.execute(query, values).fetchall()
                self.assertEqual(self.db.execute(statement("send", "rotation_statement"), ("rotated-send-key", NOW, "send", "alice", args[10], "new-access-stamp")).rowcount, 1)
                self.assertEqual(self.db.execute(cipher_update, ('{"name":"rotated","key":"rotated-key"}', NOW, "a", "alice", args[10])).rowcount, 1)
                self.assertEqual(self.db.execute(attachment_update, ("rotated-file", "rotated-file-key", NOW, "file-a", "a", "alice", args[10])).rowcount, 1)
                self.db.execute(cleanup, ("alice", args[10]))
        self.assertEqual(self.db.execute("SELECT key FROM users WHERE id='alice'").fetchone()[0], "key")
        self.assertEqual(json.loads(self.db.execute("SELECT data FROM ciphers WHERE id='a'").fetchone()[0])["key"], "wrapped-item-key")
        self.assertEqual(self.db.execute("SELECT encrypted_key FROM attachments WHERE id='file-a'").fetchone()[0], "attachment-key")
        self.assertEqual(self.db.execute("SELECT encrypted_key FROM sends WHERE id='send'").fetchone()[0], "wrapped-send-key")

    def email_args(self):
        return ("new@example.test", "new-hash", "new-salt", "rewrapped-user", 0, 600000,
                None, None, "email-write-token", NOW, "alice", "stamp", "hash",
                account_snapshot(self.db, "alice"), "device", "nonce", None, 600000, 600000)

    def seed_remember_and_prf(self):
        self.db.execute("INSERT INTO two_factors(id,user_id,provider_type,data) VALUES('remember','alice',5,'{}')")
        snapshot = account_snapshot(self.db, "alice")
        for name, stored in (("current", snapshot), ("stale", snapshot.replace('\"key\":\"key\"', '\"key\":\"previous-generation\"')), ("untagged", None)):
            self.db.execute("INSERT INTO webauthn_credentials(id,user_id,slot,name,credential_id,public_key,sign_count,credential_use,prf_status,encrypted_user_key,encrypted_private_key,account_snapshot,created_at,updated_at) VALUES(?,'alice',?,? ,?,'public',0,'login',0,'prf-user','prf-private',?,?,?)",
                            (name, {"current": 1, "stale": 2, "untagged": 3}[name], name, name, stored, OLD, OLD))
        self.db.commit()
        return snapshot

    def apply_email_batch(self, args):
        with self.db:
            changed = self.db.execute(statement("email", "change_email"), args).fetchone()
            for query in statements("email", "change_email_cleanup"):
                params = (args[3], args[10], args[13], args[8]) if query.startswith("UPDATE webauthn_credentials") else (args[10], args[8])
                self.db.execute(query, params)
        return changed

    def test_email_race_cannot_overwrite_same_stamp_v2_upgrade_or_clear_remember(self):
        self.seed_remember_and_prf()
        args = self.email_args()
        self.db.execute("UPDATE users SET key='7.concurrent-upgrade',security_version=2 WHERE id='alice'")
        self.db.commit()
        self.assertIsNone(self.apply_email_batch(args))
        user = self.db.execute("SELECT email,key FROM users WHERE id='alice'").fetchone()
        self.assertEqual(tuple(user), ("alice@example.test", "7.concurrent-upgrade"))
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM two_factors WHERE provider_type=5").fetchone()[0], 1)

    def test_email_change_rechecks_nonce_and_verified_password_hash(self):
        args = self.email_args()
        self.db.execute("UPDATE devices SET session_token='revoked' WHERE user_id='alice'")
        self.db.commit()
        self.assertIsNone(self.apply_email_batch(args))
        self.db.execute("UPDATE devices SET session_token='nonce' WHERE user_id='alice'")
        self.db.execute("UPDATE users SET master_password_hash='concurrently-replaced' WHERE id='alice'")
        self.db.commit()
        self.assertIsNone(self.apply_email_batch(args))

    def test_email_success_retags_only_current_prf_and_clears_remember_and_bridge(self):
        old = self.seed_remember_and_prf()
        self.db.execute("UPDATE users SET v2_upgrade_token='old-bridge' WHERE id='alice'")
        self.db.commit()
        args = self.email_args()
        self.assertIsNotNone(self.apply_email_batch(args))
        self.assertIsNone(self.db.execute("SELECT v2_upgrade_token FROM users WHERE id='alice'").fetchone()[0])
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM two_factors WHERE provider_type=5").fetchone()[0], 0)
        rows = {row["id"]: row for row in self.db.execute("SELECT id,account_snapshot,encrypted_user_key FROM webauthn_credentials")}
        self.assertEqual(json.loads(rows["current"]["account_snapshot"])["key"], "rewrapped-user")
        self.assertEqual(json.loads(rows["stale"]["account_snapshot"])["key"], "previous-generation")
        self.assertIsNone(rows["untagged"]["account_snapshot"])
        self.assertEqual(rows["current"]["encrypted_user_key"], "prf-user")

    def test_password_kdf_retag_uses_the_same_exact_snapshot_and_token_gate(self):
        old = self.seed_remember_and_prf()
        query = next(s for s in service_strings() if s.startswith("UPDATE webauthn_credentials SET account_snapshot="))
        self.db.execute(query, ("new-wrapper", "alice", old, "not-claimed"))
        self.assertEqual(json.loads(self.db.execute("SELECT account_snapshot FROM webauthn_credentials WHERE id='current'").fetchone()[0])["key"], "key")
        self.db.execute("UPDATE users SET account_write_token='claimed',key='new-wrapper' WHERE id='alice'")
        self.db.execute(query, ("new-wrapper", "alice", old, "claimed"))
        rows = dict(self.db.execute("SELECT id,account_snapshot FROM webauthn_credentials"))
        self.assertEqual(json.loads(rows["current"])["key"], "new-wrapper")
        self.assertEqual(json.loads(rows["stale"])["key"], "previous-generation")
        self.assertIsNone(rows["untagged"])


class PasswordVerifierSql(unittest.TestCase):
    def setUp(self):
        self.db = database()
        self.addCleanup(self.db.close)
        self.db.execute("INSERT INTO devices(user_id,device_id,name,device_type,session_token,created_at,updated_at) VALUES('alice','device','Browser',14,'nonce',?,?)", (OLD, OLD))
        self.db.execute("UPDATE users SET updated_at='2099-12-31T23:59:59.999Z' WHERE id='alice'")
        self.db.commit()

    def user(self):
        return dict(self.db.execute("SELECT * FROM users WHERE id='alice'").fetchone())

    def upgrade(self):
        old = self.user()
        query = statement("user", "migrate_password_statement").replace("{}", account_guard(9))
        return query, ("upgraded-hash", "upgraded-salt", 600000, "alice", old["master_password_hash"],
                       old["password_salt"], old["password_iterations"], old["security_stamp"], account_snapshot(self.db, "alice"))

    def claims(self):
        old = self.user()
        snapshot = account_snapshot(self.db, "alice")
        password = next(query for query in statements("account_rotation", "change_credentials")
                        if query.startswith("UPDATE users SET ")).replace("{}", account_guard(14))
        password_args = ("new-hash", "new-salt", "new-key", 0, 600000, None, None, None,
                         "new-stamp", NOW, "alice", "stamp", old["master_password_hash"], snapshot,
                         "device", "nonce", old["password_salt"], old["password_iterations"], 600000,
                         old["private_key"], old["public_key"])
        email_args = ("new@example.test", "new-hash", "new-salt", "new-key", 0, 600000,
                      None, None, "new-stamp", NOW, "alice", "stamp", old["master_password_hash"],
                      snapshot, "device", "nonce", old["password_salt"], old["password_iterations"], 600000)
        rotation, rotation_args, _ = rotation_claim(self.db)
        return [("password-upgrade", *self.upgrade()), ("password-or-client-kdf-change", password, password_args),
                ("email-change", statement("email", "change_email"), email_args),
                ("key-rotation", rotation, rotation_args)]

    def test_transparent_upgrade_preserves_cursor_stamp_and_existing_sessions(self):
        before = self.user()
        query, args = self.upgrade()
        self.assertIsNotNone(self.db.execute(query, args).fetchone())
        after = self.user()
        for name in before.keys() - {"master_password_hash", "password_salt", "password_iterations"}:
            self.assertEqual(after[name], before[name], name)
        self.assertEqual((after["master_password_hash"], after["password_salt"], after["password_iterations"]),
                         ("upgraded-hash", "upgraded-salt", 600000))
        self.assertEqual(self.db.execute("SELECT session_token FROM devices WHERE user_id='alice'").fetchone()[0], "nonce")
        self.assertEqual(self.db.execute("SELECT password_iterations FROM users WHERE id='bob'").fetchone()[0], 600000)
        self.assertIsNone(self.db.execute(query, args).fetchone())

    def test_every_credential_write_rejects_concurrent_verifier_and_envelope_changes(self):
        for operation, query, args in self.claims():
            for field, value in (("master_password_hash", "concurrent-hash"), ("password_salt", "concurrent-salt"),
                                 ("password_iterations", 1200000), ("security_stamp", "concurrent-stamp"),
                                 ("key", "concurrent-envelope")):
                with self.subTest(operation=operation, concurrent=field):
                    self.db.execute(f"UPDATE users SET {field}=? WHERE id='alice'", (value,))
                    before = self.user()
                    self.assertIsNone(self.db.execute(query, args).fetchone())
                    self.assertEqual(self.user(), before)
                    self.db.rollback()


if __name__ == "__main__":
    unittest.main(verbosity=2)
