"""Exercise the actual Rust model SQL with SQLite, without Worker bindings.

Run from the repository root: python3 tests/sql_regression.py
Application behaviors run against the complete migration chain. A separate
check verifies the generated schema snapshot matches that chain; the snapshot
is a read-only inspection artifact, not an application initialization path.
"""

import json
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

from sql_fixtures import (
    FUTURE, NOW, OLD, VAULT_REVISION, account_snapshot, apply_migrations, database,
    first_page, guard_sql, key_guard, row_guard, seed_attachment, seed_cipher, session_sql,
)
from sql_source import ROOT, literal, statement, statements


class SqlRegression(unittest.TestCase):
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
        field_names = {1: "login", 5: "sshKey", 8: "passport"}
        for kind, field in field_names.items():
            data = {"name": 'encrypted "name" 🗝', "key": "wrapped-key", "fields": [{"name": "field"}], "reprompt": 1, field: {"encrypted": field}}
            self.cipher(str(kind), kind=kind, data=data)
        self.attachment("file", "1")
        self.db.execute("UPDATE ciphers SET archived_at=? WHERE id='1'", (NOW,))
        rows = first_page(self.db, "cipher", "list_page", ("alice", 1), include_attachments=True)
        self.assertEqual(len(rows), len(field_names))
        for row in rows:
            data = json.loads(row["data"])
            self.assertEqual(data["key"], "wrapped-key")
            self.assertEqual(row["is_favorite"], 1)
            self.assertEqual(row["user_id"], "alice")
            self.assertEqual(data["fields"], [{"name": "field"}])
            self.assertEqual(data[field_names[row["cipher_type"]]], {"encrypted": field_names[row["cipher_type"]]})
            if row["id"] == "1":
                self.assertEqual(row["archived_at"], NOW)
        attachments = first_page(self.db, "attachment", "list_page", ('["1"]',))
        self.assertEqual(len(attachments), 1)
        attachment = dict(attachments[0])
        for field in ("page_rowid", "page_date", "page_has_more"):
            attachment.pop(field)
        self.assertEqual(attachment, {
            "id": "file", "cipher_id": "1", "file_name": "encrypted-file",
            "file_size_bytes": 12, "encrypted_key": "attachment-key", "created_at": OLD,
            "updated_at": OLD, "organization_id": None, "storage_key": None,
        })

    def test_cipher_update_preserves_archive_and_trash_and_owner(self):
        self.cipher()
        self.cipher("b", "bob")
        self.db.execute("UPDATE ciphers SET archived_at=?, deleted_at=? WHERE id='a'", (NOW, OLD))
        update = literal("cipher_writes", "UPDATE ciphers SET ", "save_statement")
        args = (1, '{"key":"new-item-key","name":"new"}', 0, None, NOW, NOW, "a", "alice")
        self.db.execute(update, args)
        row = self.db.execute("SELECT * FROM ciphers WHERE id='a'").fetchone()
        self.assertEqual((row["archived_at"], row["deleted_at"]), (NOW, OLD))
        self.assertEqual(json.loads(row["data"])["key"], "new-item-key")
        self.db.execute(update, (*args[:6], "b", "alice"))
        self.assertEqual(self.db.execute("SELECT updated_at FROM ciphers WHERE id='b'").fetchone()[0], OLD)

    def test_archive_single_bulk_and_ownership(self):
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
                self.db.execute(VAULT_REVISION, (NOW, "alice")).fetchall()
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
        touch, delete = statements("purge", "delete_ciphers_before")
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
            self.db.execute(VAULT_REVISION, (NOW, "alice")).fetchall()
        select = statement("storage_cleanup", "pending_batch")
        self.assertEqual({row[0] for row in self.db.execute(select)}, {"a/finalized", "staged-final", "a/pending"})
        self.assertEqual([row[0] for row in self.db.execute("SELECT id FROM ciphers")], ["b"])
        self.assertEqual([row[0] for row in self.db.execute("SELECT id FROM attachments_pending")], ["bob-file"])
        self.assertEqual(self.db.execute("SELECT updated_at FROM users WHERE id='bob'").fetchone()[0], OLD)

    def test_auth_approval_can_only_be_answered_and_consumed_once(self):
        self.auth_request()
        respond = statement("auth_request", "respond")
        self.db.execute(statement("device", "persist_session_statement"),
                        ("alice", "approving-device", "Browser", 14, "nonce", NOW))
        args = (1, "encrypted-key", "hash", NOW, "approving-device", "request", "alice", "stamp", "nonce")
        self.assertIsNone(self.db.execute(respond, args[:-1] + ("revoked",)).fetchone())
        self.assertIsNotNone(self.db.execute(respond, args).fetchone())
        self.assertIsNone(self.db.execute(respond, args).fetchone())
        consume = statement("auth_request", "consume")
        self.assertEqual(self.db.execute(consume, (NOW, "request")).fetchone()[0], "request")
        self.assertIsNone(self.db.execute(consume, (NOW, "request")).fetchone())

    def test_stamp_rotation_invalidates_pending_auth_approval(self):
        self.auth_request()
        self.db.execute("UPDATE users SET security_stamp='new-stamp' WHERE id='alice'")
        args = (1, "key", "hash", NOW, "device", "request", "alice", "stamp", "nonce")
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
        self.assertEqual([row["id"] for row in first_page(self.db, "send", "list_page", ("alice",))], ["text"])

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
