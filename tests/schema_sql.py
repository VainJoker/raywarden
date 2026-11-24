"""Schema, migration, timestamp and SQL-reader contracts."""

import json
import sqlite3
import tempfile
import unittest
from concurrent.futures import (
    ThreadPoolExecutor,
)
from contextlib import closing
from pathlib import Path
from sql_support import (
    DatabaseTestCase,
    NOW,
    OLD,
    ROOT,
    account_snapshot,
    apply_migrations,
    database,
    extract_function,
    rust_strings,
    seed_attachment,
    seed_cipher,
    source,
    statement,
    statements,
)
from threading import Barrier


CANONICAL_COLUMNS = {
    "two_factors": {"id", "user_id", "provider_type", "is_enabled", "last_used_step"},
    "users": {"two_factor_recovery_code", "is_email_verified"},
    "ciphers": {"cipher_type", "is_favorite"},
    "devices": {"device_id", "device_type", "push_id"},
    "auth_requests": {"encrypted_key", "created_at", "responded_at", "authenticated_at", "request_device_id"},
    "attachments": {"encrypted_key", "file_size_bytes"},
    "attachments_pending": {"encrypted_key", "file_size_bytes"},
    "sends": {"send_type", "encrypted_key", "file_size_bytes", "password_iterations", "expires_at", "deletes_at", "is_disabled", "upload_state", "is_email_hidden"},
}


LEGACY_COLUMNS = {
    "two_factors": {"uuid", "user_uuid", "atype", "enabled", "last_used"},
    "users": {"totp_recover", "email_verified"},
    "ciphers": {"type", "favorite"},
    "devices": {"identifier", "type", "push_uuid"},
    "auth_requests": {"enc_key", "creation_date", "response_date", "authentication_date", "request_device_identifier"},
    "attachments": {"akey", "file_size"},
    "attachments_pending": {"akey", "file_size"},
    "sends": {"type", "akey", "file_size", "password_iter", "expiration_date", "deletion_date", "disabled", "pending", "hide_email"},
}


class CanonicalSchemaSql(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.addCleanup(self.db.close)
        self.db.execute("PRAGMA foreign_keys=ON")
        apply_migrations(self.db)
        self.cipher_payload = json.dumps({"type": "opaque", "favorite": "opaque", "name": "encrypted"})
        self.account_snapshot = json.dumps({"key": "wrapped-user", "user_key_id": None, "private_key": "private", "public_key": "public", "signed_public_key": None, "security_state": None, "security_version": None, "signature_key_pair": None})
        self.remembered_devices = json.dumps({"tokens": [{"device_id": "device", "token": "sha256:opaque", "created_at": 123}]})
        for owner in ("alice", "bob"):
            self.db.execute("INSERT INTO users(id,email,is_email_verified,master_password_hash,key,private_key,public_key,security_stamp,two_factor_recovery_code,created_at,updated_at) VALUES(?,?,1,'verifier','wrapped-user','private','public','stamp','recovery','old','old')", (owner, f"{owner}@example.test"))
        self.db.execute("INSERT INTO folders(id,user_id,name,created_at,updated_at) VALUES('folder','alice','encrypted-folder','old','old')")
        self.db.execute("INSERT INTO ciphers(id,user_id,cipher_type,data,is_favorite,folder_id,created_at,updated_at) VALUES('cipher','alice',1,?,1,'folder','old','old')", (self.cipher_payload,))
        self.db.execute("INSERT INTO devices(user_id,device_id,name,device_type,session_token,push_id,created_at,updated_at) VALUES('alice','device','Browser',14,'session','relay-id','old','old')")
        self.db.execute("INSERT INTO user_api_key_sessions(user_id,device_id,session_token) VALUES('alice','device','session')")
        self.db.execute("INSERT INTO two_factors(id,user_id,provider_type,is_enabled,data,last_used_step) VALUES('factor','alice',0,1,'totp-secret',4242)")
        self.db.execute("INSERT INTO two_factors(id,user_id,provider_type,is_enabled,data,last_used_step) VALUES('remember','alice',5,1,?,0)", (self.remembered_devices,))
        self.db.execute("INSERT INTO auth_requests(id,user_id,request_device_id,device_type,request_ip,access_code,public_key,security_stamp,encrypted_key,created_at,expires_at,responded_at,authenticated_at,approved,account_snapshot) VALUES('approval','alice','request-device',14,'ip','code','public','stamp','wrapped-key','created','expires','responded','authenticated',1,?)", (self.account_snapshot,))
        self.db.execute("INSERT INTO attachments(id,cipher_id,file_name,file_size_bytes,encrypted_key,storage_key,created_at,updated_at) VALUES('ready','cipher','encrypted-name',23,'wrapped-file','attachment-old','old','old')")
        self.db.execute("INSERT INTO attachments_pending(id,cipher_id,file_name,file_size_bytes,encrypted_key,created_at,updated_at) VALUES('pending','cipher','encrypted-pending',31,'wrapped-pending','old','old')")
        self.db.execute("INSERT INTO sends(id,user_id,name,send_type,data,encrypted_key,password_hash,password_salt,password_iterations,created_at,updated_at,expires_at,deletes_at,is_disabled,is_email_hidden,access_stamp,file_id,file_size_bytes,upload_state,storage_key) VALUES('send','alice','encrypted-send',1,'opaque-json','wrapped-send','send-hash','send-salt',100000,'created','updated','expires','deletes',0,1,'send-stamp','file',47,2,'send-old')")
        self.db.commit()

    def test_canonical_columns_store_values_and_preserve_opaque_payloads(self):
        for table, expected_columns in CANONICAL_COLUMNS.items():
            names = {row["name"] for row in self.db.execute(f"PRAGMA table_info({table})")}
            self.assertTrue(expected_columns <= names, table)
            self.assertFalse(LEGACY_COLUMNS[table] & names, table)
        self.assertIsNone(self.db.execute("SELECT name FROM sqlite_schema WHERE type='table' AND name='twofactor'").fetchone())
        projections = [
            ("SELECT is_email_verified,two_factor_recovery_code FROM users WHERE id='alice'", (1, "recovery")),
            ("SELECT cipher_type,is_favorite,data FROM ciphers", (1, 1, self.cipher_payload)),
            ("SELECT device_id,device_type,push_id FROM devices", ("device", 14, "relay-id")),
            ("SELECT id,user_id,provider_type,is_enabled,data,last_used_step FROM two_factors WHERE id='factor'", ("factor", "alice", 0, 1, "totp-secret", 4242)),
            ("SELECT data FROM two_factors WHERE id='remember'", (self.remembered_devices,)),
            ("SELECT request_device_id,encrypted_key,created_at,responded_at,authenticated_at,account_snapshot FROM auth_requests", ("request-device", "wrapped-key", "created", "responded", "authenticated", self.account_snapshot)),
            ("SELECT file_size_bytes,encrypted_key FROM attachments", (23, "wrapped-file")),
            ("SELECT file_size_bytes,encrypted_key FROM attachments_pending", (31, "wrapped-pending")),
            ("SELECT send_type,encrypted_key,file_size_bytes,password_iterations,expires_at,deletes_at,is_disabled,upload_state,is_email_hidden,data FROM sends", (1, "wrapped-send", 47, 100000, "expires", "deletes", 0, 2, 1, "opaque-json")),
        ]
        for query, expected in projections:
            self.assertEqual(tuple(self.db.execute(query).fetchone()), expected, query)
        self.assertEqual(self.db.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_unique_check_and_composite_foreign_keys_enforce_constraints(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("INSERT INTO two_factors(id,user_id,provider_type,data) VALUES('duplicate','alice',0,'secret')")
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("UPDATE sends SET upload_state=3")
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("UPDATE attachments SET file_size_bytes=-1")
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("UPDATE ciphers SET cipher_type=9")
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("INSERT INTO user_api_key_sessions(user_id,device_id,session_token) VALUES('alice','missing','session')")
        self.db.execute("DELETE FROM devices WHERE user_id='alice' AND device_id='device'")
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM user_api_key_sessions").fetchone()[0], 0)
        self.assertEqual(self.db.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_ownership_and_file_cleanup_triggers_preserve_isolation(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("INSERT INTO ciphers(id,user_id,cipher_type,data,folder_id,created_at,updated_at) VALUES('foreign','bob',1,'opaque','folder','old','old')")
        self.db.execute("UPDATE attachments SET storage_key='attachment-new' WHERE id='ready'")
        self.db.execute("UPDATE sends SET storage_key='send-new' WHERE id='send'")
        self.assertEqual({row[0] for row in self.db.execute("SELECT object_key FROM storage_cleanup_jobs")}, {"attachment-old", "send-old"})
        self.db.execute("DELETE FROM users WHERE id='alice'")
        self.assertEqual({row[0] for row in self.db.execute("SELECT object_key FROM storage_cleanup_jobs")}, {"attachment-old", "attachment-new", "send-old", "send-new", "cipher/pending"})
        self.assertEqual([row[0] for row in self.db.execute("SELECT id FROM users")], ["bob"])
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM two_factors").fetchone()[0], 0)
        self.assertEqual(self.db.execute("PRAGMA foreign_key_check").fetchall(), [])


class SqlSourceReader(unittest.TestCase):
    def test_function_boundaries_ignore_literals_comments_and_nested_functions(self):
        rust = r'''
// fn query() { panic!("not a function"); }
impl Store {
    pub fn query<'a>(value: &'a str) -> &'a str {
        let json = r##"{ "fn query()": "}" }"##;
        let closing = '}'; // }
        /* fn query() { } */
        fn nested() { let value = "}"; }
        if true { nested(); }
        "SELECT first"
    }
    fn next() { "DELETE next"; }
}
'''
        found = extract_function(rust, "query")
        self.assertIn('"SELECT first"', found)
        self.assertNotIn('DELETE next', found)
        self.assertEqual(list(rust_strings(found))[-1], "SELECT first")

    def test_missing_and_duplicate_functions_fail_instead_of_picking_one(self):
        for rust in ["fn other() {}", "impl A {fn query() {}} impl B {fn query() {}}"]:
            with self.assertRaisesRegex(AssertionError, "Expected one"):
                extract_function(rust, "query", "fixture.rs")
        with self.assertRaisesRegex(AssertionError, "Unclosed"):
            extract_function("fn query() {", "query")

    def test_declarations_do_not_capture_the_following_function(self):
        rust = 'trait Store { fn query(); fn other() { "DELETE unrelated"; } }'
        with self.assertRaisesRegex(AssertionError, "Missing function body"):
            extract_function(rust, "query")
        self.assertIn('"SELECT array"', extract_function(
            'fn query() -> [u8; 8] { "SELECT array"; [0; 8] }', "query"))

    def test_strings_preserve_raw_and_rust_escape_forms(self):
        rust = r'''r"raw\path" r###"SELECT '{raw}'"### "line\n\u{1F680}\x41\'\"\\\0"'''
        self.assertEqual(list(rust_strings(rust)), ["raw\\path", "SELECT '{raw}'", 'line\n🚀A\'"\\\0'])
        self.assertEqual(list(rust_strings('"SELECT \\\n    value"')), ["SELECT value"])

    def test_comment_strings_and_char_literals_are_not_sql(self):
        rust = '''// "DELETE comment"
/* "INSERT comment" */
let c = '{'; let query = "SELECT real";
'''
        self.assertEqual(list(rust_strings(rust)), ["SELECT real"])
        nested = '/* outer /* nested */ "DELETE hidden" */ fn query() {}'
        with self.assertRaisesRegex(AssertionError, "Nested Rust block comments"):
            list(rust_strings(nested))
        with self.assertRaisesRegex(AssertionError, "Nested Rust block comments"):
            extract_function(nested, "query")

    def test_unknown_source_requires_explicit_registration(self):
        with self.assertRaisesRegex(AssertionError, "Unregistered SQL source"):
            source("../unregistered")


class GlobalDomainsCacheSql(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        apply_migrations(self.db)
        self.addCleanup(self.db.close)

    def claim(self, now):
        rows = self.db.execute(
            statement("domains", "claim_global_domains_refresh"),
            (now + 3600, now),
        ).fetchall()
        self.db.commit()
        return bool(rows)

    def replace(self, groups, now):
        delete, insert, update = statements("domains", "replace_global_domains")
        with self.db:
            self.db.execute(delete)
            self.db.execute(insert, (json.dumps(groups),))
            self.db.execute(update, (now + 86400,))

    def groups(self, excluded="[]", settings=True):
        query = statement("domains", "query_global_equivalent_domains")
        return json.loads(self.db.execute(query, (excluded, settings)).fetchone()[0])

    def test_only_single_metadata_row_is_allowed(self):
        self.assertTrue(self.claim(1000))
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute(
                "INSERT INTO global_domains_cache VALUES (2, 0)"
            )

    def test_first_use_and_failure_backoff_are_shared(self):
        self.assertTrue(self.claim(1000))
        self.assertFalse(self.claim(1000))
        self.assertFalse(self.claim(4599))
        self.assertTrue(self.claim(4600))
        self.assertEqual(self.groups(), [])
        self.assertEqual(
            self.db.execute("SELECT COUNT(*) FROM global_domains_cache").fetchone()[0],
            1,
        )

    def test_success_replaces_all_rows_and_waits_a_day(self):
        self.assertTrue(self.claim(1000))
        self.replace([{"type": 99, "domains": ["old.test"]}], 1000)
        self.assertFalse(self.claim(87399))
        self.assertTrue(self.claim(87400))
        expected = [
            {"type": 20, "domains": ["first.test", "second.test"]},
            {"type": 10, "domains": ["other.test"]},
        ]
        self.replace(expected, 87400)
        self.assertEqual(
            self.groups(), [dict(group, excluded=False) for group in expected]
        )
        self.assertFalse(self.claim(173799))
        self.assertTrue(self.claim(173800))

    def test_failed_refresh_keeps_previous_rows_for_reads(self):
        self.assertTrue(self.claim(1000))
        self.replace([{"type": 1, "domains": ["cached.test"]}], 1000)
        before = self.groups()
        self.assertTrue(self.claim(87400))
        # A failed fetch/validation never reaches replace_global_domains.
        self.assertEqual(self.groups(), before)
        self.assertFalse(self.claim(90999))
        self.assertTrue(self.claim(91000))

    def test_failed_batch_rolls_back_delete_and_keeps_retry_deadline(self):
        self.assertTrue(self.claim(1000))
        self.replace([{"type": 1, "domains": ["cached.test"]}], 1000)
        before = self.groups()
        self.assertTrue(self.claim(87400))
        with self.assertRaises(sqlite3.IntegrityError):
            self.replace([
                {"type": 2, "domains": ["new.test"]},
                {"type": 2, "domains": ["duplicate.test"]},
            ], 87400)
        self.assertEqual(self.groups(), before)
        self.assertFalse(self.claim(90999))
        self.assertTrue(self.claim(91000))

    def test_settings_marks_repeated_exclusions_once_and_sync_filters_them(self):
        self.assertTrue(self.claim(1000))
        self.replace([
            {"type": 20, "domains": ["first.test"]},
            {"type": 1, "domains": ["second.test"]},
            {"type": 10, "domains": ["third.test"]},
        ], 1000)
        self.assertEqual(self.groups("[1,1]"), [
            {"type": 20, "domains": ["first.test"], "excluded": False},
            {"type": 1, "domains": ["second.test"], "excluded": True},
            {"type": 10, "domains": ["third.test"], "excluded": False},
        ])
        self.assertEqual(self.groups("[1,1]", settings=False), [
            {"type": 20, "domains": ["first.test"], "excluded": False},
            {"type": 10, "domains": ["third.test"], "excluded": False},
        ])


CUTOFF = "2026-11-13T03:00:00.123Z"


DATES = [
    ("past-z", "2026-11-13T03:00:00.122Z"),
    ("past-plus", "2026-11-13T11:00:00.122+08:00"),
    ("past-minus", "2026-11-12T22:00:00.122-05:00"),
    ("equal-z", CUTOFF),
    ("equal-plus", "2026-11-13T11:00:00.123+08:00"),
    ("equal-minus", "2026-11-12T22:00:00.123-05:00"),
    ("equal-utc", "2026-11-13T03:00:00.123000+00:00"),
    ("future", "2026-11-13T03:00:00.124Z"),
]


PAST = {name for name, _ in DATES if name.startswith("past-")}


COUNT_LAST_WRITE = statement("cipher_mutation", "batch_count_last_write")


class StoredTimestampSql(DatabaseTestCase):
    def cipher(self, name="cipher"):
        seed_cipher(self.db, name, data='{"name":"encrypted","login":{}}', created=CUTOFF, updated=CUTOFF)

    def test_pending_cleanup_keeps_equal_instants_with_every_legacy_offset(self):
        self.cipher()
        for name, date in DATES:
            seed_attachment(self.db, name, "cipher", pending=True, key="wrapped-key", created=date)
        delete = statement("attachment", "purge_pending_before")
        with self.db:
            self.db.execute(delete, (CUTOFF,))
            self.assertEqual(self.db.execute(COUNT_LAST_WRITE).fetchone()[0], len(PAST))
        self.assertEqual({row[0] for row in self.db.execute("SELECT object_key FROM storage_cleanup_jobs")}, {f"cipher/{name}" for name in PAST})
        self.assertEqual({row[0] for row in self.db.execute("SELECT id FROM attachments_pending")}, {name for name, _ in DATES} - PAST)

    def test_trash_purge_is_strictly_before_the_same_absolute_cutoff(self):
        for name, date in DATES:
            self.cipher(name)
            self.db.execute("UPDATE ciphers SET deleted_at=? WHERE id=?", (date, name))
        touch, delete = statements("purge", "delete_ciphers_before")
        with self.db:
            self.db.execute(touch, ("2026-11-14T03:00:00.123Z", CUTOFF))
            self.db.execute(delete, (CUTOFF,))
            self.assertEqual(self.db.execute(COUNT_LAST_WRITE).fetchone()[0], len(PAST))
        self.assertEqual({row[0] for row in self.db.execute("SELECT id FROM ciphers")}, {name for name, _ in DATES} - PAST)

    def test_auth_approval_expiry_uses_instants_and_expires_at_equality(self):
        for name, date in DATES:
            self.db.execute(statement("auth_request", "insert"),
                            (name, "alice", "device", 2, "ip", "code", "public", "stamp", "2026-11-13T02:55:00.123Z", date, account_snapshot(self.db, "alice")))
        rows = self.db.execute(statement("auth_request", "list_pending_for_user"), ("alice", CUTOFF)).fetchall()
        self.assertEqual({row["id"] for row in rows}, {"future"})
        self.db.execute(statement("auth_request", "purge_expired"), (CUTOFF,))
        self.assertEqual({row[0] for row in self.db.execute("SELECT id FROM auth_requests")}, {"future"})

    def test_email_verification_and_initial_key_id_advance_a_legacy_future_cursor(self):
        self.db.execute("UPDATE users SET updated_at=? WHERE id='alice'",
                        ("2099-01-01T08:00:00.000+08:00",))
        self.db.execute(statement("email", "update_verified"),
                        (CUTOFF, "alice", "alice@example.test", "stamp"))
        self.assertEqual(self.db.execute("SELECT updated_at FROM users WHERE id='alice'").fetchone()[0],
                         "2099-01-01T00:00:00.001Z")
        self.db.execute(statement("account_keys", "set_key_id"),
                        ("fixture-key-id", CUTOFF, "alice"))
        self.assertEqual(self.db.execute("SELECT updated_at FROM users WHERE id='alice'").fetchone()[0],
                         "2099-01-01T00:00:00.002Z")

    def test_webauthn_expiry_never_accepts_equal_instants_with_a_later_text_offset(self):
        for name, date in DATES:
            self.db.execute(statement("webauthn", "insert"),
                            (name, name, "assert.login", "alice", "stamp", "device", "session", "vault.test", "https://vault.test", date, account_snapshot(self.db, "alice")))
            found = self.db.execute(statement("webauthn", "find_challenge"), (name, "assert.login", CUTOFF)).fetchone()
            self.assertEqual(found is not None, name == "future", name)
        self.db.execute(statement("webauthn", "purge"), (CUTOFF,))
        self.assertEqual({row[0] for row in self.db.execute("SELECT id FROM webauthn_challenges")}, {"future"})

    def test_send_cleanup_accepts_existing_offset_and_fraction_formats(self):
        for name, date in DATES:
            self.db.execute("INSERT INTO sends(id,user_id,name,send_type,data,encrypted_key,created_at,updated_at,deletes_at,access_stamp) VALUES(?,'alice','encrypted',0,'{}','wrapped',?,?,?,'stamp')", (name, CUTOFF, CUTOFF, date))
        rows = self.db.execute(statement("send", "cleanup_candidates"), (CUTOFF, "2026-11-12T03:00:00.123Z")).fetchall()
        self.assertEqual({row["id"] for row in rows}, {name for name, _ in DATES if name != "future"})


class SchemaParity(unittest.TestCase):
    def test_schema_snapshot_matches_migrations_without_data_or_history(self):
        migrated = sqlite3.connect(":memory:")
        snapshot = sqlite3.connect(":memory:")
        self.addCleanup(migrated.close)
        self.addCleanup(snapshot.close)
        migrated.execute("PRAGMA foreign_keys=ON")
        snapshot.execute("PRAGMA foreign_keys=ON")
        apply_migrations(migrated)
        snapshot.executescript((ROOT / "sql/schema.sql").read_text())

        objects = """
            SELECT type, name, tbl_name, sql FROM sqlite_schema
            WHERE name NOT GLOB 'sqlite_*'
            ORDER BY type, name
        """
        self.assertEqual(snapshot.execute(objects).fetchall(), migrated.execute(objects).fetchall())
        for label, db in (("migrations", migrated), ("snapshot", snapshot)):
            with self.subTest(source=label):
                self.assertIsNone(db.execute("SELECT name FROM sqlite_schema WHERE name='d1_migrations'").fetchone())
                for (table,) in db.execute("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT GLOB 'sqlite_*'"):
                    quoted = table.replace('"', '""')
                    self.assertEqual(db.execute(f'SELECT COUNT(*) FROM "{quoted}"').fetchone()[0], 0, table)
                self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])


class AccountSchema(unittest.TestCase):
    def db(self):
        db = sqlite3.connect(":memory:")
        self.addCleanup(db.close)
        db.execute("PRAGMA foreign_keys=ON")
        apply_migrations(db)
        return db

    @staticmethod
    def insert(db, user, email=None):
        db.execute("INSERT INTO users(id,email,master_password_hash,key,private_key,public_key,created_at,updated_at) VALUES(?,?,'hash','key','private','public',?,?)", (user, email or f"{user}@example.test", OLD, OLD))

    def test_accounts_are_independent_but_email_uniqueness_is_case_insensitive(self):
        db = self.db()
        self.insert(db, "alice")
        self.insert(db, "bob")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "users.email"):
            self.insert(db, "duplicate", "ALICE@example.test")
        self.assertEqual(db.execute("SELECT COUNT(*) FROM users").fetchone()[0], 2)

    def test_competing_different_accounts_both_commit(self):
        self.race(("alice", "bob"), 2)

    def test_competing_same_email_commits_once(self):
        self.race(("alice", "alice"), 1)

    def race(self, emails, expected):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "accounts.sqlite"
            with closing(sqlite3.connect(path)) as db, db:
                apply_migrations(db)
            barrier = Barrier(2)
            def register(item):
                number, email = item
                with closing(sqlite3.connect(path, timeout=10)) as db, db:
                    barrier.wait(timeout=10)
                    try:
                        self.insert(db, str(number), f"{email}@example.test")
                        return 1
                    except sqlite3.IntegrityError as error:
                        self.assertIn("users.email", str(error))
                        return 0
            with ThreadPoolExecutor(max_workers=2) as pool:
                self.assertEqual(sum(pool.map(register, enumerate(emails))), expected)

    def test_folder_ownership_is_enforced_on_insert_update_and_owner_change(self):
        db = database()
        self.addCleanup(db.close)
        db.execute("INSERT INTO folders VALUES('folder','alice','encrypted',?,?)", (OLD, OLD))
        with self.assertRaisesRegex(sqlite3.IntegrityError, "Folder does not belong"):
            seed_cipher(db, "foreign", "bob", folder_id="folder")
        seed_cipher(db, "cipher", "alice", folder_id="folder")
        for sql in ["UPDATE ciphers SET user_id='bob' WHERE id='cipher'",
                    "UPDATE folders SET user_id='bob' WHERE id='folder'"]:
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute(sql)
        seed_cipher(db, "bob-cipher", "bob")
        with self.assertRaises(sqlite3.IntegrityError):
            db.execute("UPDATE ciphers SET folder_id='folder' WHERE id='bob-cipher'")
        db.execute("DELETE FROM folders WHERE id='folder'")
        self.assertIsNone(db.execute("SELECT folder_id FROM ciphers WHERE id='cipher'").fetchone()[0])
        self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_available_email_query_uses_current_whitelist_and_existing_accounts(self):
        db = self.db()
        sql = statement("user", "has_available_email")
        self.insert(db, "alice")
        self.assertIsNone(db.execute(sql, (json.dumps(["alice@example.test"]),)).fetchone())
        self.assertIsNotNone(db.execute(sql, (json.dumps(["ALICE@example.test", "bob@example.test"]),)).fetchone())
        self.assertIsNone(db.execute(sql, ("[]",)).fetchone())

    def test_account_deletion_preserves_other_vault_and_enqueues_file_cleanup(self):
        db = database()
        self.addCleanup(db.close)
        for user in ("alice", "bob"):
            seed_cipher(db, user, user)
            seed_attachment(db, user, user)
        db.execute("DELETE FROM users WHERE id='alice'")
        self.assertEqual([row[0] for row in db.execute("SELECT id FROM ciphers")], ["bob"])
        self.assertEqual([row[0] for row in db.execute("SELECT object_key FROM storage_cleanup_jobs")], ["alice/alice"])
        self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_cleanup_queries_use_expression_indexes(self):
        db = self.db()
        for table, column, index, predicate in [
            ("ciphers", "deleted_at", "idx_ciphers_deleted_at", "deleted_at IS NOT NULL AND "),
            ("sends", "deletes_at", "idx_sends_deletes_at", ""),
            ("attachments_pending", "created_at", "idx_attachments_pending_created_at", ""),
            ("auth_requests", "expires_at", "idx_auth_requests_expires_at", ""),
            ("webauthn_challenges", "expires_at", "idx_webauthn_challenges_expires_at", ""),
        ]:
            plan = db.execute(f"EXPLAIN QUERY PLAN DELETE FROM {table} WHERE {predicate}julianday({column}) < julianday(?)", (NOW,)).fetchall()
            self.assertIn(index, str(plan))


class PasswordCostSchema(unittest.TestCase):
    db = AccountSchema.db
    insert = staticmethod(AccountSchema.insert)
    def test_new_accounts_default_to_current_server_cost(self):
        db = self.db()
        self.insert(db, "owner")
        self.assertEqual(db.execute("SELECT password_iterations FROM users").fetchone()[0], 600000)

    def test_stored_cost_is_a_positive_u32_independent_of_client_kdf(self):
        db = self.db()
        self.insert(db, "owner")
        for value in (None, 0, -1, 4294967296, 100000.5, "invalid"):
            with self.subTest(cost=value), self.assertRaises(sqlite3.IntegrityError):
                db.execute("UPDATE users SET password_iterations=?", (value,))
        for value in (1, 100000, 600000, 1200000, 4294967295):
            db.execute("UPDATE users SET password_iterations=?,kdf_type=1,kdf_iterations=3", (value,))
            self.assertEqual(db.execute("SELECT password_iterations,kdf_iterations FROM users").fetchone(), (value, 3))


if __name__ == "__main__":
    unittest.main(verbosity=2)
