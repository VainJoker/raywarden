"""Account credentials, session and identity transaction contracts."""

import json
import re
import sqlite3
import unittest
from sql_support import (
    DatabaseTestCase,
    FUTURE,
    NOW,
    OLD,
    account_guard,
    account_snapshot,
    apply_migrations,
    database,
    literal,
    rust_strings,
    seed_attachment,
    seed_cipher,
    send_guard,
    source,
    source as read_source,
    statement,
    statements,
)


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


class AccountV2Sql(DatabaseTestCase):
    def setUp(self):
        super().setUp()
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


class PasswordVerifierSql(DatabaseTestCase):
    def setUp(self):
        super().setUp()
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


class ApiKeySql(DatabaseTestCase):
    def setUp(self):
        super().setUp()
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


def clear_recovery_sql():
    query = statement("two_factor", "clear_recovery_statement")
    constants = dict(re.findall(r"const (REMEMBER_PROVIDER|FIRST_INTERNAL_PROVIDER): i32 = (\d+);", source("two_factor")))
    return query.format(**constants)


class TwoFactorAtomicSql(DatabaseTestCase):
    def setUp(self):
        super().setUp()
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


class AtomicTwoFactorRecovery(DatabaseTestCase):
    def setUp(self):
        super().setUp()
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


class JwtKeySql(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        self.db.execute("PRAGMA foreign_keys=ON")
        apply_migrations(self.db)
        self.select = statement("jwt_keys", "find")
        self.insert = statement("jwt_keys", "initialize_if_allowed")
        self.wrap = statement("jwt_keys", "wrap_if_current")

    def test_legacy_wrapping_is_an_atomic_compare_and_swap_of_both_fields(self):
        original = (" original-access ", " original-refresh ")
        self.db.execute(self.insert, (*original, 0))
        wrapped = ("v1.first-access", "v1.first-refresh")
        self.assertEqual(self.db.execute(self.wrap, (*wrapped, *original)).rowcount, 1)
        # A competing wrapper of the same plaintext cannot replace the winner.
        self.assertEqual(self.db.execute(self.wrap, ("v1.loser-access", "v1.loser-refresh", *original)).rowcount, 0)
        self.assertEqual(self.db.execute(self.select).fetchone(), wrapped)

    def test_legacy_wrapping_cannot_overwrite_a_change_to_either_field(self):
        for changed in [("changed-access", "original-refresh"), ("original-access", "changed-refresh")]:
            with self.subTest(changed=changed):
                self.db.execute("DELETE FROM jwt_keys")
                self.db.execute(self.insert, (*changed, 0))
                self.assertEqual(self.db.execute(self.wrap, ("v1.access", "v1.refresh", "original-access", "original-refresh")).rowcount, 0)
                self.assertEqual(self.db.execute(self.select).fetchone(), changed)

    def test_first_insert_wins_and_following_initializers_cannot_replace_keys(self):
        self.assertIsNone(self.db.execute(self.select).fetchone())
        self.assertEqual(self.db.execute(self.insert, ("first-access", "first-refresh", 0)).rowcount, 1)
        self.assertEqual(self.db.execute(self.insert, ("other-access", "other-refresh", 1)).rowcount, 0)
        self.assertEqual(self.db.execute(self.select).fetchone(), ("first-access", "first-refresh"))
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM jwt_keys").fetchone()[0], 1)

    def test_account_deletion_keeps_the_independent_signing_and_wrapping_keys(self):
        self.db.execute(self.insert, ("existing-access", "existing-refresh", 0))
        self.db.execute("INSERT INTO users(id,email,master_password_hash,key,private_key,public_key,created_at,updated_at) VALUES ('owner','owner@example.test','hash','wrapped','private','public','now','now')")
        self.db.execute("DELETE FROM users WHERE id='owner'")
        self.assertEqual(self.db.execute(self.select).fetchone(), ("existing-access", "existing-refresh"))
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("INSERT INTO jwt_keys VALUES ('another', 'access', 'refresh')")
        self.assertEqual(self.db.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_missing_keys_cannot_be_randomly_recreated_for_an_existing_account(self):
        self.db.execute("INSERT INTO users(id,email,master_password_hash,key,private_key,public_key,created_at,updated_at) VALUES ('owner','owner@example.test','hash','wrapped','private','public','now','now')")
        self.assertEqual(self.db.execute(self.insert, ("random-access", "random-refresh", 0)).rowcount, 0)
        self.assertIsNone(self.db.execute(self.select).fetchone())
        # Explicit import preserves the old wrapping key even on a populated DB.
        self.assertEqual(self.db.execute(self.insert, (" original-access ", " original-refresh ", 1)).rowcount, 1)
        self.assertEqual(self.db.execute(self.select).fetchone(), (" original-access ", " original-refresh "))


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


NOW = "2026-11-13T03:00:00.000Z"


WEBAUTHN_FUTURE = "2099-01-01T00:00:00.000Z"


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
                         "device", session, "vault.example", "https://vault.example", WEBAUTHN_FUTURE,
                         account_snapshot(self.db, user) if user else None))
        self.db.commit()

    def credential(self, count=0):
        self.db.execute("INSERT INTO webauthn_credentials(id,user_id,slot,name,credential_id,public_key,sign_count,credential_use,created_at,updated_at) VALUES('credential','owner',1,'Key','credential-wire-id','public-key',?,'2fa',?,?)", (count, NOW, NOW))
        self.db.commit()

    def assertion(self, old, new, user="owner"):
        queries = statements("webauthn", "assertion_statements")
        with self.db:
            first = self.db.execute(queries[0], (new, "challenge-id", NOW, "credential", old, user, "credential-wire-id", "public-key", "2fa")).rowcount
            second = self.db.execute(queries[1], (NOW, "challenge-id", "credential")).rowcount
        return first, second

    def register(self):
        queries=statements("webauthn","register")
        args=[("new-credential","owner",1,"Key","wire-id","public",0,"2fa",2,None,None,None,"challenge-id",NOW,account_snapshot(self.db, "owner")),
              (NOW,"challenge-id","new-credential"),
              ("factor-id","owner","2fa","new-credential","challenge-id"),
              (NOW,"owner","2fa","recovery-code","new-credential","challenge-id")]
        with self.db:
            return [self.db.execute(query,params).rowcount for query,params in zip(queries,args,strict=True)]

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

    def test_prf_final_write_requires_current_account_session_and_accepted_assertion(self):
        query, args = self.prf_update()
        for mutation in (
            "UPDATE devices SET session_token='revoked' WHERE user_id='owner'",
            "UPDATE users SET security_stamp='revoked' WHERE id='owner'",
            "UPDATE users SET key='concurrent-wrapper' WHERE id='owner'",
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

        self.assertIsNotNone(self.db.execute(query, args).fetchone())
        self.assertEqual(self.db.execute("SELECT encrypted_public_key,encrypted_user_key,encrypted_private_key FROM webauthn_credentials").fetchone(),
                         ("new-public", "new-user", "new-private"))


class PushDevices(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.execute("PRAGMA foreign_keys=ON")
        apply_migrations(self.db)
        for user in ("alice", "bob"):
            self.db.execute("INSERT INTO users(id,email,master_password_hash,key,private_key,public_key,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)", (user, f"{user}@test", "hash", "key", "private", "public", "now", "now"))
            self.db.execute("INSERT INTO devices(user_id,device_id,name,device_type,session_token,created_at,updated_at) VALUES(?,?,?,?,?,?,?)", (user, "same-client-id", "phone", 0, f"session-{user}", "now", "now"))

    def tearDown(self):
        self.db.close()

    def test_uuid_assignment_is_stable_and_user_scoped(self):
        ensure = statement("push", "assign_uuid")
        self.assertEqual(self.db.execute(ensure, ("relay-alice", "alice", "same-client-id")).fetchone()[0], "relay-alice")
        self.assertEqual(self.db.execute(ensure, ("replacement", "alice", "same-client-id")).fetchone()[0], "relay-alice")
        self.assertEqual(self.db.execute(ensure, ("relay-bob", "bob", "same-client-id")).fetchone()[0], "relay-bob")
        self.assertIsNone(self.db.execute(ensure, ("intruder", "alice", "other-device")).fetchone())

    def test_push_lookup_and_cleanup_list_cannot_cross_users(self):
        ensure = statement("push", "assign_uuid")
        self.db.execute(ensure, ("relay-alice", "alice", "same-client-id")).fetchall()
        self.db.execute(ensure, ("relay-bob", "bob", "same-client-id")).fetchall()
        self.db.row_factory = sqlite3.Row
        lookup = statement("push", "find_for_user")
        row = self.db.execute(lookup, ("alice", "same-client-id")).fetchone()
        self.assertEqual(row["push_id"], "relay-alice")
        self.assertNotIn("session_token", row.keys())
        listing = statement("push", "list_for_user_statement")
        self.assertEqual([r["push_id"] for r in self.db.execute(listing, ("bob",))], ["relay-bob"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
