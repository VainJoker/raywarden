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


from sql_source import ROOT, function_source, rust_strings, statement, statements
NOW = "2026-11-13T03:00:00.000Z"
OLD = "2020-01-01T00:00:00.000Z"
FUTURE = "2026-11-14T03:00:00.000Z"


def cipher_rows_query(attachments=True, where_clause="", order_clause=""):
    literals = list(rust_strings(function_source("cipher", "cipher_row_sql")))
    template = next(text for text in literals if text.startswith("SELECT c.*"))
    attachment_expr = next(text for text in literals if "SELECT CASE WHEN COUNT" in text) if attachments else "NULL"
    return template.replace("{attachments_expr}", attachment_expr).replace("{where_clause}", where_clause).replace("{order_clause}", order_clause)


def apply_migrations(db, *, legacy_multi_user=False):
    """Exercise migration SQL; Wrangler owns history and pending-file selection."""
    for path in sorted((ROOT / "sql/migrations").glob("*.sql")):
        db.executescript(path.read_text())
    if legacy_multi_user:
        # Deliberately inconsistent historical fixtures retain multiple owners
        # so authorization regressions still exercise cross-user isolation.
        db.execute("DROP INDEX users_single_owner")


def database():
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    apply_migrations(db, legacy_multi_user=True)
    for user in ("alice", "bob"):
        db.execute("INSERT INTO users (id,email,master_password_hash,key,private_key,public_key,security_stamp,created_at,updated_at) VALUES (?,?,'hash','key','private','public','stamp',?,?)", (user, f"{user}@example.test", OLD, OLD))
    return db


def seed_cipher(db, cipher_id, user="alice", *, cipher_type=1, data=None,
                favorite=0, folder_id=None, created=OLD, updated=OLD):
    """Test data only; behavior assertions use production guarded statements."""
    if not isinstance(data, str):
        data = json.dumps(data if data is not None else {})
    db.execute("INSERT INTO ciphers(id,user_id,organization_id,type,data,favorite,folder_id,created_at,updated_at) VALUES(?,?,NULL,?,?,?,?,?,?)",
               (cipher_id, user, cipher_type, data, favorite, folder_id, created, updated))


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
        seed_cipher(self.db, cipher_id, user, cipher_type=kind, data=data, favorite=1)

    def attachment(self, attachment_id, cipher_id="a", pending=False):
        if pending:
            self.db.execute(statement("attachment", "insert_pending"), (attachment_id, cipher_id, "encrypted-file", 12, "attachment-key", OLD, None))
        else:
            self.db.execute(statement("attachment", "insert_finalized"), (attachment_id, cipher_id, "encrypted-file", 12, "attachment-key", OLD, OLD, None))

    def auth_request(self, request_id="request", user="alice"):
        self.db.execute(statement("auth_request", "insert"), (request_id, user, "request-device", 2, "ip", "code", "public", "stamp", NOW, FUTURE, account_snapshot(self.db, user)))

    def send(self, send_id="send", user="alice", size=0, pending=0, quota=None):
        return self.db.execute(statement("send", "insert_statement"), (send_id, user, "encrypted-name", None, int(size > 0), '{"text":"encrypted"}', "wrapped-send-key", None, None, None, 1, 0, NOW, NOW, None, FUTURE, 0, 0, "access-stamp", "file" if size else None, size, pending, quota)).fetchone()

    def test_cipher_rows_preserve_encrypted_fields_owner_and_attachment_metadata(self):
        field_names = {1: "login", 2: "secureNote", 3: "card", 4: "identity", 5: "sshKey", 6: "bankAccount", 7: "driversLicense", 8: "passport"}
        for kind, field in field_names.items():
            data = {"name": 'encrypted "name" 🗝', "key": "wrapped-key", "fields": [{"name": "field"}], "reprompt": 1, field: {"encrypted": field}}
            self.cipher(str(kind), kind=kind, data=data)
        self.attachment("file", "1")
        self.db.execute("UPDATE ciphers SET archived_at=? WHERE id='1'", (NOW,))
        for row in self.db.execute(cipher_rows_query(order_clause="ORDER BY c.type")):
            data = json.loads(row["data"])
            self.assertEqual(data["key"], "wrapped-key")
            self.assertEqual(row["favorite"], 1)
            self.assertEqual(row["user_id"], "alice")
            self.assertEqual(data["fields"], [{"name": "field"}])
            self.assertEqual(data[field_names[row["type"]]], {"encrypted": field_names[row["type"]]})
            if row["id"] == "1":
                self.assertEqual(row["archived_at"], NOW)
                attachments = json.loads(row["attachments_json"])
                self.assertEqual(attachments[0]["key"], "attachment-key")
                self.assertEqual(attachments[0]["size"], "12")
                self.assertIsNone(attachments[0]["url"])
            else:
                self.assertIsNone(row["attachments_json"])
        row = self.db.execute(cipher_rows_query(False, "WHERE c.id='1'")).fetchone()
        self.assertIsNone(row["attachments_json"])

    def test_cipher_update_preserves_archive_and_trash_and_owner(self):
        self.cipher()
        self.cipher("b", "bob")
        self.db.execute("UPDATE ciphers SET archived_at=?, deleted_at=? WHERE id='a'", (NOW, OLD))
        from sql_source import literal
        update = literal("cipher_http", "UPDATE ciphers SET ", "save_cipher")
        args = (1, '{"key":"new-item-key","name":"new"}', 0, None, NOW, NOW, "a", "alice")
        self.db.execute(update, args)
        row = self.db.execute("SELECT * FROM ciphers WHERE id='a'").fetchone()
        self.assertEqual((row["archived_at"], row["deleted_at"]), (NOW, OLD))
        self.assertEqual(json.loads(row["data"])["key"], "new-item-key")
        self.db.execute(update, (*args[:6], "b", "alice"))
        self.assertEqual(self.db.execute("SELECT updated_at FROM ciphers WHERE id='b'").fetchone()[0], OLD)

    def test_archive_single_bulk_and_ownership(self):
        from cipher_v2_sql import REVISION
        from send_compat_sql import guard_sql, key_guard, session_sql
        from sql_source import literal
        self.cipher()
        self.cipher("b", "bob")
        self.cipher("c")
        self.db.execute(statement("device", "start_session"), ("alice", "device", "browser", 2, "session", NOW))
        self.db.commit()
        suffix = literal("cipher_changes", " WHERE user_id=", "mutate_selected")
        predicate = literal("cipher_changes", "(SELECT COUNT(*) FROM ciphers c JOIN json_each", "mutate_selected")
        def apply(ids, archive):
            rows = [dict(self.db.execute("SELECT * FROM ciphers WHERE id=?", (id,)).fetchone()) for id in ids]
            owner = dict(self.db.execute("SELECT * FROM users WHERE id='alice'").fetchone())
            prefix = "UPDATE ciphers SET archived_at=?3" if archive else "UPDATE ciphers SET archived_at=NULL"
            query = literal("cipher_changes", prefix, "mutate_selected").replace("{suffix}", suffix)
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
        cutoff = "2026-10-14T03:00:00.000Z"
        self.assertEqual({tuple(row) for row in self.db.execute(statement("purge", "deleted_cipher_attachment_keys"), (cutoff,))}, {("a", "finalized"), ("a", "pending")})
        self.assertEqual([tuple(row) for row in self.db.execute(statement("purge", "stale_pending_keys"), (cutoff,))], [("a", "pending")])
        touch, delete = statements("purge", "delete_ciphers_before")
        self.db.execute(touch, (NOW, cutoff))
        self.db.execute(delete, (cutoff,))
        self.assertEqual([row[0] for row in self.db.execute("SELECT id FROM ciphers")], ["b"])
        self.assertEqual(self.db.execute("SELECT updated_at FROM users WHERE id='alice'").fetchone()[0], NOW)
        self.assertEqual(self.db.execute("SELECT updated_at FROM users WHERE id='bob'").fetchone()[0], OLD)
        for table in ("attachments", "attachments_pending"):
            self.assertEqual(self.db.execute(f"SELECT count(*) FROM {table}").fetchone()[0], 0)

    def test_manual_attachment_cleanup_is_complete_and_user_scoped(self):
        self.cipher()
        self.cipher("b", "bob")
        self.attachment("finalized")
        self.attachment("pending", pending=True)
        self.attachment("bob-file", "b", pending=True)
        self.db.execute("UPDATE attachments SET storage_key='staged-final' WHERE id='finalized'")
        keys = self.db.execute(statement("attachment", "list_attachment_keys_for_user"), ("alice",))
        self.assertEqual({tuple(row) for row in keys}, {("a", "finalized", "staged-final"), ("a", "pending", None)})
        source = function_source("attachment", "list_attachment_keys_for_cipher_ids_json")
        literals = list(rust_strings(source))
        sql = next(text for text in literals if text.startswith("SELECT"))
        sql += next(text for text in literals if text.startswith(" AND c.user_id"))
        keys = self.db.execute(sql, ('{"ids":["a","b"]}', "$.ids", "alice"))
        self.assertEqual({tuple(row) for row in keys}, {("a", "finalized", "staged-final"), ("a", "pending", None)})

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
        start = statement("device", "start_session")
        for user in ("alice", "bob"):
            self.db.execute(start, (user, "device", "browser", 2, f"session-{user}", NOW))
            self.auth_request(user, user)
            self.db.execute("INSERT INTO twofactor (uuid,user_uuid,atype,data) VALUES (?,?,5,'{}')", (user, user))
        update, devices, requests, remember = statements("device", "revoke_all")
        self.db.execute(update, ("new-stamp", NOW, "alice"))
        for sql in (devices, requests, remember):
            self.db.execute(sql, ("alice",))
        self.assertEqual(self.db.execute("SELECT security_stamp FROM users WHERE id='alice'").fetchone()[0], "new-stamp")
        self.assertEqual(self.db.execute("SELECT security_stamp FROM users WHERE id='bob'").fetchone()[0], "stamp")
        self.assertEqual(self.db.execute("SELECT user_id FROM devices").fetchone()[0], "bob")
        self.assertEqual(self.db.execute("SELECT user_id FROM auth_requests").fetchone()[0], "bob")
        self.assertEqual(self.db.execute("SELECT user_uuid FROM twofactor").fetchone()[0], "bob")

    def test_send_quota_reserves_pending_files_and_owner_lists_hide_them(self):
        self.assertIsNotNone(self.send("first", size=7, pending=1, quota=10))
        self.assertIsNone(self.send("second", size=4, pending=1, quota=10))
        self.assertIsNotNone(self.send("other", user="bob", size=10, pending=1, quota=10))
        self.assertEqual(self.db.execute(statement("send", "list_for_user"), ("alice",)).fetchall(), [])
        self.assertIsNotNone(self.send("text"))
        self.assertEqual([row["id"] for row in self.db.execute(statement("send", "list_for_user"), ("alice",))], ["text"])

    def test_send_access_limit_and_stamp_are_checked_by_conditional_update(self):
        self.send()
        consume = statement("send", "consume_access")
        self.assertIsNone(self.db.execute(consume, (NOW, "send", "old-stamp", None)).fetchone())
        self.assertEqual(self.db.execute(consume, (NOW, "send", "access-stamp", None)).fetchone()[0], 1)
        self.assertIsNone(self.db.execute(consume, (NOW, "send", "access-stamp", None)).fetchone())
        self.db.execute("UPDATE sends SET access_count=0, disabled=1")
        self.assertIsNone(self.db.execute(consume, (NOW, "send", "access-stamp", None)).fetchone())
        self.db.execute("UPDATE sends SET disabled=0, deletion_date=?", (OLD,))
        self.assertIsNone(self.db.execute(consume, (NOW, "send", "access-stamp", None)).fetchone())

    def test_rotation_attachment_writes_require_matching_cipher_and_write_token(self):
        from account_v2_sql import rotation_claim
        from sql_source import literal
        self.cipher()
        self.cipher("b", "bob")
        self.attachment("file-a")
        self.attachment("file-b", "b")
        self.db.execute(statement("device", "start_session"), ("alice", "device", "browser", 2, "nonce", NOW))
        claim, args, guards = rotation_claim(self.db)
        cipher_update = literal("account_rotation", "UPDATE ciphers SET data=", "rotate")
        attachment_update = literal("account_rotation", "UPDATE attachments SET ", "rotate")
        self.db.commit()
        with self.db:
            self.assertIsNotNone(self.db.execute(claim, args).fetchone())
            for query, values in guards:
                self.db.execute(query, values).fetchall()
            self.assertEqual(self.db.execute(cipher_update, ('{"name":"rotated","key":"rotated-key"}', NOW, "a", "alice", args[10])).rowcount, 1)
            self.assertEqual(self.db.execute(attachment_update, ("rotated-file", "rotated-file-key", NOW, "file-a", "a", "alice", args[10])).rowcount, 1)
            self.db.execute(attachment_update, ("bad-file", "bad-key", NOW, "file-b", "a", "alice", args[10]))
            self.db.execute(attachment_update, ("bad-file", "bad-key", NOW, "file-b", "b", "alice", "wrong-write-token"))
        rows = {row["id"]: row["akey"] for row in self.db.execute("SELECT * FROM attachments")}
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
        self.db.execute(statement("device", "start_session"), ("alice", "device", "browser", 2, "nonce", NOW))
        # Inject a late failure at the real rotation batch's approval cleanup.
        self.db.execute("CREATE TEMP TRIGGER reject_rotation_cleanup BEFORE DELETE ON auth_requests BEGIN SELECT RAISE(ABORT,'injected cleanup failure'); END")
        claim, args, guards = rotation_claim(self.db)
        cipher_update = literal("account_rotation", "UPDATE ciphers SET data=", "rotate")
        attachment_update = literal("account_rotation", "UPDATE attachments SET ", "rotate")
        cleanup = literal("account_rotation", "DELETE FROM auth_requests WHERE user_id=?1 AND EXISTS", "rotate")
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
        self.assertEqual(self.db.execute("SELECT akey FROM attachments WHERE id='file-a'").fetchone()[0], "attachment-key")
        self.assertEqual(self.db.execute("SELECT akey FROM sends WHERE id='send'").fetchone()[0], "wrapped-send-key")

    def test_file_upload_pointer_can_only_be_finalized_once(self):
        from send_compat_sql import snapshot, finalize_upload
        self.send(size=7, pending=1)
        self.db.execute(statement("device", "start_session"), ("alice", "device", "browser", 2, "session", NOW))
        before = snapshot(self.db)
        finalize_upload(self.db, before, staged="winner")
        with self.assertRaises(sqlite3.OperationalError):
            finalize_upload(self.db, before, staged="loser")
        self.assertEqual(snapshot(self.db)["storage_key"], "winner")

    def test_file_upload_finalization_rechecks_stamp_and_device_revocation(self):
        from send_compat_sql import snapshot, finalize_upload
        self.send(size=7, pending=1)
        start = statement("device", "start_session")
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
        from send_compat_sql import snapshot, send_guard
        self.send(size=7, pending=1)
        before = snapshot(self.db)
        for column, value in (("user_id", "bob"), ("file_id", "wrong-file"), ("akey", "rotated-key")):
            with self.db:
                self.db.execute(f"UPDATE sends SET {column}=? WHERE id='send'", (value,))
                with self.assertRaises(sqlite3.OperationalError):
                    self.db.execute(*send_guard(before, upload=True))
                self.db.execute(f"UPDATE sends SET {column}=? WHERE id='send'", (before[column],))

    def test_send_failed_upload_retains_its_original_pending_reservation(self):
        from send_compat_sql import snapshot, finalize_upload
        self.send(size=7, pending=1)
        self.db.execute(statement("device", "start_session"), ("alice", "device", "browser", 2, "session", NOW))
        before = snapshot(self.db)
        # Reading/streaming an attempt never claims or changes the row anymore.
        self.assertEqual(snapshot(self.db), before)
        finalize_upload(self.db, before, staged="retry")
        self.assertEqual(snapshot(self.db)["pending"], 0)

    def test_send_upload_finalization_releases_unused_reserved_quota(self):
        from send_compat_sql import snapshot, finalize_upload
        self.send(size=7, pending=1, quota=10)
        self.db.execute(statement("device", "start_session"), ("alice", "device", "browser", 2, "session", NOW))
        finalize_upload(self.db, snapshot(self.db), size=3)
        self.assertIsNotNone(self.send("second", size=7, pending=1, quota=10))
        self.db.execute(statement("send", "delete_pending"), ("send", "alice"))
        self.assertEqual(snapshot(self.db)["file_size"], 3)

    def test_failed_legacy_send_reservation_can_be_discarded(self):
        self.send(size=7, pending=1, quota=10)
        self.db.execute(statement("send", "delete_pending"), ("send", "alice"))
        self.assertIsNotNone(self.send("replacement", size=10, pending=1, quota=10))


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


class SingleOwnerSchema(unittest.TestCase):
    migration = ROOT / "sql/migrations/0010_single_user.sql"

    def db(self, *, before_single_owner=False):
        db = sqlite3.connect(":memory:")
        self.addCleanup(db.close)
        db.execute("PRAGMA foreign_keys=ON")
        if before_single_owner:
            for path in sorted(self.migration.parent.glob("*.sql")):
                if path == self.migration:
                    break
                db.executescript(path.read_text())
        else:
            apply_migrations(db)
        return db

    @staticmethod
    def insert(db, user):
        db.execute("INSERT INTO users(id,email,master_password_hash,key,private_key,public_key,created_at,updated_at) VALUES(?,?,'hash','key','private','public',?,?)", (user, f"{user}@example.test", OLD, OLD))

    def test_full_chain_rejects_a_second_owner_with_another_email(self):
        db = self.db()
        self.insert(db, "owner")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "users_single_owner"):
            self.insert(db, "another")
        self.assertEqual(db.execute("SELECT id,email FROM users").fetchall(), [("owner", "owner@example.test")])

    def test_single_existing_owner_is_preserved_when_adding_constraint(self):
        db = self.db(before_single_owner=True)
        self.insert(db, "owner")
        before = db.execute("SELECT * FROM users").fetchall()
        db.executescript(self.migration.read_text())
        self.assertEqual(db.execute("SELECT * FROM users").fetchall(), before)
        with self.assertRaisesRegex(sqlite3.IntegrityError, "users_single_owner"):
            self.insert(db, "another")

    def test_existing_multiple_owners_stop_migration_without_deleting_accounts(self):
        db = self.db(before_single_owner=True)
        self.insert(db, "owner")
        self.insert(db, "another")
        before = db.execute("SELECT * FROM users ORDER BY id").fetchall()
        with self.assertRaisesRegex(sqlite3.IntegrityError, "users_single_owner"):
            db.executescript(self.migration.read_text())
        self.assertEqual(db.execute("SELECT * FROM users ORDER BY id").fetchall(), before)
        self.assertIsNone(db.execute("SELECT name FROM sqlite_schema WHERE name='users_single_owner'").fetchone())

    def test_competing_first_account_inserts_commit_only_one_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "owners.sqlite"
            with sqlite3.connect(path) as db:
                apply_migrations(db)
            barrier = Barrier(2)

            def register(user):
                db = sqlite3.connect(path, timeout=10)
                try:
                    barrier.wait(timeout=10)
                    try:
                        with db:
                            self.insert(db, user)
                        return True
                    except sqlite3.IntegrityError as error:
                        self.assertIn("users_single_owner", str(error))
                        return False
                finally:
                    db.close()

            with ThreadPoolExecutor(max_workers=2) as pool:
                self.assertEqual(sum(pool.map(register, ("owner", "another"))), 1)
            with sqlite3.connect(path) as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM users").fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
