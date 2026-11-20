"""Exercise the actual Rust model SQL with SQLite, without Worker bindings.

Run from the repository root: python3 tests/sql_regression.py
Application behaviors run against the complete migration chain. A separate
check verifies the generated schema snapshot matches that chain; the snapshot
is a read-only inspection artifact, not an application initialization path.
"""

import json
import re
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier


from sql_source import ROOT, function_source, literal, rust_strings, statement, statements
NOW = "2026-11-13T03:00:00.000Z"
OLD = "2020-01-01T00:00:00.000Z"
FUTURE = "2026-11-14T03:00:00.000Z"


def cipher_rows_query(attachments=True, where_clause="", order_clause=""):
    literals = list(rust_strings(function_source("cipher", "cipher_row_sql")))
    template = next(text for text in literals if text.startswith("SELECT c.*"))
    attachment_expr = next(text for text in literals if "SELECT CASE WHEN COUNT" in text) if attachments else "NULL"
    return template.replace("{attachments_expr}", attachment_expr).replace("{where_clause}", where_clause).replace("{order_clause}", order_clause)


def trash_purge_statements():
    touch, delete = statements("purge", "delete_ciphers_before")
    revision = literal("cipher_mutation", "CASE WHEN julianday(updated_at)")
    return touch.replace("{NEXT_USER_REVISION_SQL}", revision), delete


def apply_migrations(db):
    """Exercise migration SQL; Wrangler owns history and pending-file selection."""
    for path in sorted((ROOT / "sql/migrations").glob("*.sql")):
        db.executescript(path.read_text())


def database():
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    apply_migrations(db)
    for user in ("alice", "bob"):
        db.execute("INSERT INTO users (id,email,master_password_hash,key,private_key,public_key,security_stamp,created_at,updated_at) VALUES (?,?,'hash','key','private','public','stamp',?,?)", (user, f"{user}@example.test", OLD, OLD))
    return db


def seed_cipher(db, cipher_id, user="alice", *, cipher_type=1, data=None,
                is_favorite=0, folder_id=None, created=OLD, updated=OLD):
    """Test data only; behavior assertions use production guarded statements."""
    if not isinstance(data, str):
        data = json.dumps(data if data is not None else {})
    db.execute("INSERT INTO ciphers(id,user_id,organization_id,cipher_type,data,is_favorite,folder_id,created_at,updated_at) VALUES(?,?,NULL,?,?,?,?,?,?)",
               (cipher_id, user, cipher_type, data, is_favorite, folder_id, created, updated))


def seed_attachment(db, attachment_id, cipher_id, *, pending=False,
                    name="encrypted-file", key="attachment-key", created=OLD):
    """Fixture data only; finalization/deletion assertions use production SQL."""
    table = "attachments_pending" if pending else "attachments"
    db.execute(f"INSERT INTO {table}(id,cipher_id,file_name,file_size_bytes,encrypted_key,created_at,updated_at,organization_id) VALUES(?,?,?,12,?,?,?,NULL)",
               (attachment_id, cipher_id, name, key, created, created))


def account_snapshot(db, user):
    columns = ("key", "user_key_id", "private_key", "public_key", "signed_public_key",
               "security_state", "security_version", "signature_key_pair")
    row = db.execute(f"SELECT {','.join(columns)} FROM users WHERE id=?", (user,)).fetchone()
    return json.dumps(dict(zip(columns, row)), separators=(",", ":"))


class SqlBehavior:
    def setUp(self):
        self.db = database()
        self.addCleanup(self.db.close)

    def cipher(self, cipher_id="a", user="alice", kind=1, data=None):
        data = data if data is not None else {"name": "encrypted", "key": "wrapped-item-key", "login": {"password": "encrypted-password"}}
        seed_cipher(self.db, cipher_id, user, cipher_type=kind, data=data, is_favorite=1)

    def attachment(self, attachment_id, cipher_id="a", pending=False):
        seed_attachment(self.db, attachment_id, cipher_id, pending=pending)

    def auth_request(self, request_id="request", user="alice"):
        self.db.execute(statement("auth_request", "insert"), (request_id, user, "request-device", 2, "ip", "code", "public", "stamp", NOW, FUTURE, account_snapshot(self.db, user)))

    def send(self, send_id="send", user="alice", size=0, pending=0):
        self.db.execute(statement("send", "insert_statement"), (send_id, user, "encrypted-name", None, int(size > 0), '{"text":"encrypted"}', "wrapped-send-key", None, None, None, 1, 0, NOW, NOW, None, FUTURE, 0, 0, "access-stamp", "file" if size else None, size, pending))

    def test_cipher_rows_preserve_encrypted_fields_owner_and_attachment_metadata(self):
        field_names = {1: "login", 2: "secureNote", 3: "card", 4: "identity", 5: "sshKey", 6: "bankAccount", 7: "driversLicense", 8: "passport"}
        for kind, field in field_names.items():
            data = {"name": 'encrypted "name" 🗝', "key": "wrapped-key", "fields": [{"name": "field"}], "reprompt": 1, field: {"encrypted": field}}
            self.cipher(str(kind), kind=kind, data=data)
        self.attachment("file", "1")
        self.db.execute("UPDATE ciphers SET archived_at=? WHERE id='1'", (NOW,))
        for row in self.db.execute(cipher_rows_query(order_clause="ORDER BY c.cipher_type")):
            data = json.loads(row["data"])
            self.assertEqual(data["key"], "wrapped-key")
            self.assertEqual(row["is_favorite"], 1)
            self.assertEqual(row["user_id"], "alice")
            self.assertEqual(data["fields"], [{"name": "field"}])
            self.assertEqual(data[field_names[row["cipher_type"]]], {"encrypted": field_names[row["cipher_type"]]})
            if row["id"] == "1":
                self.assertEqual(row["archived_at"], NOW)
                attachments = json.loads(row["attachments_json"])
                self.assertEqual(attachments, [{
                    "id": "file", "cipher_id": "1", "file_name": "encrypted-file",
                    "file_size_bytes": 12, "encrypted_key": "attachment-key", "created_at": OLD,
                    "updated_at": OLD, "organization_id": None, "storage_key": None,
                }])
            else:
                self.assertIsNone(row["attachments_json"])
        row = self.db.execute(cipher_rows_query(False, "WHERE c.id='1'")).fetchone()
        self.assertIsNone(row["attachments_json"])

    def test_cipher_update_preserves_archive_and_trash_and_owner(self):
        self.cipher()
        self.cipher("b", "bob")
        self.db.execute("UPDATE ciphers SET archived_at=?, deleted_at=? WHERE id='a'", (NOW, OLD))
        from sql_source import literal
        update = literal("cipher_writes", "UPDATE ciphers SET ", "save_statement")
        args = (1, '{"key":"new-item-key","name":"new"}', 0, None, NOW, NOW, "a", "alice")
        self.db.execute(update, args)
        row = self.db.execute("SELECT * FROM ciphers WHERE id='a'").fetchone()
        self.assertEqual((row["archived_at"], row["deleted_at"]), (NOW, OLD))
        self.assertEqual(json.loads(row["data"])["key"], "new-item-key")
        self.db.execute(update, (*args[:6], "b", "alice"))
        self.assertEqual(self.db.execute("SELECT updated_at FROM ciphers WHERE id='b'").fetchone()[0], OLD)

    def test_archive_single_bulk_and_ownership(self):
        from cipher_v2_sql import REVISION
        from send_transactions_sql import guard_sql, key_guard, session_sql
        from sql_source import literal
        self.cipher()
        self.cipher("b", "bob")
        self.cipher("c")
        self.db.execute(statement("device", "persist_session_statement"), ("alice", "device", "browser", 2, "session", NOW))
        self.db.commit()
        suffix = literal("cipher_changes", " WHERE user_id=", "selected_mutation")
        predicate = literal("cipher_changes", "(SELECT COUNT(*) FROM ciphers c JOIN json_each", "selected_snapshot_guards")
        def apply(ids, archive):
            rows = [dict(self.db.execute("SELECT * FROM ciphers WHERE id=?", (id,)).fetchone()) for id in ids]
            owner = dict(self.db.execute("SELECT * FROM users WHERE id='alice'").fetchone())
            prefix = "UPDATE ciphers SET archived_at=?3" if archive else "UPDATE ciphers SET archived_at=NULL"
            query = literal("cipher_changes", prefix, "selected_mutation").replace("{suffix}", suffix)
            with self.db:
                self.db.execute(session_sql(), ("alice", "stamp", "device", "session")).fetchall()
                self.db.execute(*key_guard(owner)).fetchall()
                self.db.execute(guard_sql(predicate), ("alice", json.dumps(rows))).fetchall()
                self.assertEqual(self.db.execute(query, ("alice", json.dumps(ids), NOW)).rowcount, len(ids))
                self.db.execute(REVISION, (NOW, "alice")).fetchall()
        apply(["a"], True)
        self.assertEqual(self.db.execute("SELECT archived_at FROM ciphers WHERE id='a'").fetchone()[0], NOW)
        apply(["a", "c"], False)
        self.assertIsNone(self.db.execute("SELECT archived_at FROM ciphers WHERE id='a'").fetchone()[0])
        with self.assertRaises(sqlite3.OperationalError):
            apply(["a", "b"], True)
        self.assertIsNone(self.db.execute("SELECT archived_at FROM ciphers WHERE id='a'").fetchone()[0])
        self.assertEqual(self.db.execute("SELECT updated_at FROM ciphers WHERE id='b'").fetchone()[0], OLD)

    def test_cleanup_includes_pending_objects_and_updates_only_affected_users(self):
        self.cipher()
        self.cipher("b", "bob")
        self.attachment("finalized")
        self.attachment("pending", pending=True)
        self.db.execute("UPDATE ciphers SET deleted_at=? WHERE id='a'", (OLD,))
        self.db.execute("UPDATE users SET updated_at=? WHERE id='alice'", (FUTURE,))
        cutoff = "2026-10-14T03:00:00.000Z"
        touch, delete = trash_purge_statements()
        with self.db:
            self.db.execute(touch, (NOW, cutoff))
            self.db.execute(delete, (cutoff,))
            self.assertEqual(self.db.execute(statement("cipher_mutation", "batch_count_last_write")).fetchone()[0], 1)
        self.assertEqual([row[0] for row in self.db.execute("SELECT id FROM ciphers")], ["b"])
        self.assertEqual(self.db.execute("SELECT updated_at FROM users WHERE id='alice'").fetchone()[0], "2026-11-14T03:00:00.001Z")
        self.assertEqual(self.db.execute("SELECT updated_at FROM users WHERE id='bob'").fetchone()[0], OLD)
        self.assertEqual({row[0] for row in self.db.execute("SELECT object_key FROM storage_cleanup_jobs")}, {"a/finalized", "a/pending"})
        for table in ("attachments", "attachments_pending"):
            self.assertEqual(self.db.execute(f"SELECT count(*) FROM {table}").fetchone()[0], 0)

    def test_manual_attachment_cleanup_is_complete_and_user_scoped(self):
        from cipher_v2_sql import REVISION, row_guard
        from send_transactions_sql import key_guard, session_sql
        from sql_source import literal
        self.cipher()
        self.cipher("b", "bob")
        self.attachment("finalized")
        self.attachment("pending", pending=True)
        self.attachment("bob-file", "b", pending=True)
        self.db.execute("UPDATE attachments SET storage_key='staged-final' WHERE id='finalized'")
        self.db.execute(statement("device", "persist_session_statement"), ("alice", "device", "browser", 2, "session", NOW))
        owner = dict(self.db.execute("SELECT * FROM users WHERE id='alice'").fetchone())
        cipher = dict(self.db.execute("SELECT * FROM ciphers WHERE id='a'").fetchone())
        suffix = literal("cipher_changes", " WHERE user_id=", "selected_mutation")
        delete = literal("cipher_changes", "DELETE FROM ciphers", "selected_mutation").replace("{suffix}", suffix)
        self.db.commit()
        with self.db:
            self.db.execute(session_sql(), ("alice", "stamp", "device", "session")).fetchall()
            self.db.execute(*key_guard(owner)).fetchall()
            self.db.execute(*row_guard(cipher)).fetchall()
            self.db.execute(delete, ("alice", '["a"]'))
            self.db.execute(REVISION, (NOW, "alice")).fetchall()
        select = statement("storage_cleanup", "pending_batch")
        self.assertEqual({row[0] for row in self.db.execute(select)}, {"a/finalized", "staged-final", "a/pending"})
        self.assertEqual([row[0] for row in self.db.execute("SELECT id FROM ciphers")], ["b"])
        self.assertEqual([row[0] for row in self.db.execute("SELECT id FROM attachments_pending")], ["bob-file"])
        self.assertEqual(self.db.execute("SELECT updated_at FROM users WHERE id='bob'").fetchone()[0], OLD)

    def test_auth_approval_can_only_be_answered_and_consumed_once(self):
        self.auth_request()
        respond = statement("auth_request", "respond")
        args = (1, "encrypted-key", "hash", NOW, "approving-device", "request", "alice")
        self.assertIsNotNone(self.db.execute(respond, args).fetchone())
        self.assertIsNone(self.db.execute(respond, args).fetchone())
        consume = statement("auth_request", "consume")
        self.assertEqual(self.db.execute(consume, (NOW, "request")).fetchone()[0], "request")
        self.assertIsNone(self.db.execute(consume, (NOW, "request")).fetchone())

    def test_stamp_rotation_invalidates_pending_auth_approval(self):
        self.auth_request()
        self.db.execute("UPDATE users SET security_stamp='new-stamp' WHERE id='alice'")
        args = (1, "key", "hash", NOW, "device", "request", "alice")
        self.assertIsNone(self.db.execute(statement("auth_request", "respond"), args).fetchone())
        self.db.execute("UPDATE auth_requests SET approved=1")
        self.assertIsNone(self.db.execute(statement("auth_request", "consume"), (NOW, "request")).fetchone())

    def test_revoke_all_sessions_preserves_other_user(self):
        start = statement("device", "persist_session_statement")
        for user in ("alice", "bob"):
            self.db.execute(start, (user, "device", "browser", 2, f"session-{user}", NOW))
            self.auth_request(user, user)
            self.db.execute("INSERT INTO two_factors (id,user_id,provider_type,data) VALUES (?,?,5,'{}')", (user, user))
        update, devices, requests, remember = statements("device", "revoke_all_with_stamp")
        self.db.execute(update, ("new-stamp", NOW, "alice"))
        for sql in (devices, requests, remember):
            self.db.execute(sql, ("alice",))
        self.assertEqual(self.db.execute("SELECT security_stamp FROM users WHERE id='alice'").fetchone()[0], "new-stamp")
        self.assertEqual(self.db.execute("SELECT security_stamp FROM users WHERE id='bob'").fetchone()[0], "stamp")
        self.assertEqual(self.db.execute("SELECT user_id FROM devices").fetchone()[0], "bob")
        self.assertEqual(self.db.execute("SELECT user_id FROM auth_requests").fetchone()[0], "bob")
        self.assertEqual(self.db.execute("SELECT user_id FROM two_factors").fetchone()[0], "bob")

    def test_send_owner_list_hides_pending_files_and_other_owners(self):
        self.send("pending", size=7, pending=1)
        self.send("other", user="bob", size=10)
        self.send("text")
        self.assertEqual([row["id"] for row in self.db.execute(statement("send", "list_for_user"), ("alice",))], ["text"])

    def test_send_access_limit_and_stamp_are_checked_by_conditional_update(self):
        self.send()
        consume = statement("send", "consume_access")
        self.assertIsNone(self.db.execute(consume, (NOW, "send", "old-stamp", None)).fetchone())
        self.assertEqual(self.db.execute(consume, (NOW, "send", "access-stamp", None)).fetchone()[0], 1)
        self.assertIsNone(self.db.execute(consume, (NOW, "send", "access-stamp", None)).fetchone())
        self.db.execute("UPDATE sends SET access_count=0, is_disabled=1")
        self.assertIsNone(self.db.execute(consume, (NOW, "send", "access-stamp", None)).fetchone())
        self.db.execute("UPDATE sends SET is_disabled=0, deletes_at=?", (OLD,))
        self.assertIsNone(self.db.execute(consume, (NOW, "send", "access-stamp", None)).fetchone())

    def test_rotation_attachment_writes_require_matching_cipher_and_write_token(self):
        from account_v2_sql import rotation_claim
        from sql_source import literal
        self.cipher()
        self.cipher("b", "bob")
        self.attachment("file-a")
        self.attachment("file-b", "b")
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
        value = self.db.execute(cipher_rows_query(where_clause="WHERE c.id='a'")).fetchone()
        self.assertEqual(json.loads(value["data"])["key"], "rotated-key")

    def test_failed_rotation_rolls_back_content_and_wrapping_keys_together(self):
        from account_v2_sql import rotation_claim
        from sql_source import literal
        self.cipher()
        self.attachment("file-a")
        self.send()
        self.auth_request()
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

    def test_file_upload_pointer_can_only_be_finalized_once(self):
        from send_transactions_sql import snapshot, finalize_upload
        self.send(size=7, pending=1)
        self.db.execute(statement("device", "persist_session_statement"), ("alice", "device", "browser", 2, "session", NOW))
        before = snapshot(self.db)
        finalize_upload(self.db, before, staged="winner")
        with self.assertRaises(sqlite3.OperationalError):
            finalize_upload(self.db, before, staged="loser")
        self.assertEqual(snapshot(self.db)["storage_key"], "winner")

    def test_file_upload_finalization_rechecks_stamp_and_device_revocation(self):
        from send_transactions_sql import snapshot, finalize_upload
        self.send(size=7, pending=1)
        start = statement("device", "persist_session_statement")
        self.db.execute(start, ("alice", "device", "browser", 2, "session", NOW))
        before = snapshot(self.db)
        owner = dict(self.db.execute("SELECT * FROM users WHERE id='alice'").fetchone())
        self.db.execute("UPDATE users SET security_stamp='new-stamp' WHERE id='alice'")
        with self.assertRaises(sqlite3.OperationalError):
            finalize_upload(self.db, before, owner=owner)
        self.db.execute("UPDATE users SET security_stamp='stamp' WHERE id='alice'")
        self.db.execute("DELETE FROM devices WHERE user_id='alice'")
        with self.assertRaises(sqlite3.OperationalError):
            finalize_upload(self.db, before, owner=owner)
        self.db.execute(start, ("alice", "device", "browser", 2, "new-session", NOW))
        with self.assertRaises(sqlite3.OperationalError):
            finalize_upload(self.db, before, owner=owner)

    def test_send_upload_rechecks_file_metadata_and_wrapped_key(self):
        from send_transactions_sql import snapshot, send_guard
        self.send(size=7, pending=1)
        before = snapshot(self.db)
        for column, value in (("user_id", "bob"), ("file_id", "wrong-file"), ("encrypted_key", "rotated-key")):
            with self.db:
                self.db.execute(f"UPDATE sends SET {column}=? WHERE id='send'", (value,))
                with self.assertRaises(sqlite3.OperationalError):
                    self.db.execute(*send_guard(before, upload=True))
                self.db.execute(f"UPDATE sends SET {column}=? WHERE id='send'", (before[column],))

class MigratedSchema(SqlBehavior, unittest.TestCase):
    pass


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
            with sqlite3.connect(path) as db:
                apply_migrations(db)
            barrier = Barrier(2)
            def register(item):
                number, email = item
                with sqlite3.connect(path, timeout=10) as db:
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
