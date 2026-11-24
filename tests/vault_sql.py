"""Vault, attachment, Send and storage transaction contracts."""

import json
import sqlite3
import tempfile
import unittest
from concurrent.futures import (
    ThreadPoolExecutor,
)
from pathlib import Path
from sql_support import (
    DatabaseTestCase,
    FUTURE,
    NOW,
    OLD,
    ROOT,
    VAULT_REVISION,
    account_snapshot,
    apply_migrations,
    extract_function,
    first_page,
    guard_sql,
    key_guard,
    literal,
    row_guard,
    rust_strings,
    seed_attachment,
    seed_cipher,
    send_guard,
    session_sql,
    source_literals,
    statement,
    statements,
)
from threading import Barrier


class SqlRegression(DatabaseTestCase):
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


CIPHERS = "cipher_writes"


IMPORT = "vault_import"


ATTACHMENTS = "attachment"


class CipherTransactions(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        self.db.execute("INSERT INTO devices(user_id,device_id,name,device_type,session_token,created_at,updated_at) VALUES('alice','device','test',1,'session',?,?)", (OLD, OLD))
        self.db.execute("INSERT INTO ciphers(id,user_id,cipher_type,data,created_at,updated_at) VALUES('cipher','alice',1,?, ?, ?)", (json.dumps({"name": "encrypted", "login": {}}), OLD, OLD))
        self.db.commit()

    def row(self):
        return dict(self.db.execute("SELECT * FROM ciphers WHERE id='cipher'").fetchone())

    def owner(self):
        return dict(self.db.execute("SELECT * FROM users WHERE id='alice'").fetchone())

    def test_exact_snapshot_detects_same_revision_data_and_archive_changes(self):
        for column, value in (("data", '{"name":"other"}'), ("archived_at", NOW), ("is_favorite", 1), ("deleted_at", NOW), ("cipher_type", 8), ("created_at", NOW)):
            with self.subTest(column=column):
                before = self.row()
                self.db.execute(f"UPDATE ciphers SET {column}=? WHERE id='cipher'", (value,))
                self.db.commit()
                with self.assertRaises(sqlite3.OperationalError), self.db:
                    self.db.execute(*row_guard(before)).fetchall()
                    self.db.execute("UPDATE ciphers SET data='lost update' WHERE id='cipher'")
                self.assertEqual(self.row()[column], value)
                self.db.execute(f"UPDATE ciphers SET {column}=? WHERE id='cipher'", (before[column],))
                self.db.commit()

    def test_same_stamp_account_upgrade_rolls_back_encrypted_write(self):
        before = self.owner()
        self.db.execute("UPDATE users SET key='v2-wrap',security_version=2 WHERE id='alice'")
        self.db.commit()
        original = self.row()["data"]
        with self.assertRaises(sqlite3.OperationalError), self.db:
            self.db.execute(*key_guard(before)).fetchall()
            self.db.execute("UPDATE ciphers SET data='old-envelope' WHERE id='cipher'")
        self.assertEqual(self.row()["data"], original)

    def test_revoked_device_nonce_or_stamp_fences_every_vault_write(self):
        for change in ("UPDATE devices SET session_token='revoked'", "UPDATE users SET security_stamp='revoked' WHERE id='alice'"):
            with self.subTest(change=change):
                self.db.execute(change)
                self.db.commit()
                with self.assertRaises(sqlite3.OperationalError), self.db:
                    self.db.execute(session_sql(), ("alice", "stamp", "device", "session")).fetchall()
                    self.db.execute("DELETE FROM ciphers WHERE id='cipher'")
                self.assertIsNotNone(self.row())
                self.db.execute("UPDATE devices SET session_token='session'")
                self.db.execute("UPDATE users SET security_stamp='stamp' WHERE id='alice'")
                self.db.commit()

    def test_sync_cursor_increases_for_same_or_out_of_order_request_times(self):
        self.db.execute("UPDATE users SET updated_at=? WHERE id='alice'", (NOW,))
        previous = NOW
        for request_time in (NOW, OLD, NOW):
            current = self.db.execute(VAULT_REVISION, (request_time, "alice")).fetchone()[0]
            self.assertGreater(current, previous)
            previous = current

    def test_bulk_snapshot_checks_every_selected_row_without_row_bind_expansion(self):
        rows = []
        for i in range(450):
            self.db.execute("INSERT INTO ciphers(id,user_id,cipher_type,data,created_at,updated_at) VALUES(?,'alice',1,'{}',?,?)", (f"bulk-{i}", OLD, OLD))
            rows.append(dict(self.db.execute("SELECT * FROM ciphers WHERE id=?", (f"bulk-{i}",)).fetchone()))
        self.db.commit()
        predicate = literal("cipher_changes", "(SELECT COUNT(*) FROM ciphers c JOIN json_each")
        self.db.execute("UPDATE ciphers SET archived_at=? WHERE id='bulk-449'", (NOW,))
        self.db.commit()
        with self.assertRaises(sqlite3.OperationalError), self.db:
            for start in range(0, len(rows), 200):
                self.db.execute(guard_sql(predicate), ("alice", json.dumps(rows[start:start + 200]))).fetchall()
            self.db.execute("DELETE FROM ciphers WHERE id LIKE 'bulk-%'")
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM ciphers WHERE id LIKE 'bulk-%'").fetchone()[0], 450)

    def test_import_json_chunks_preserve_blob_type_folder_and_archive(self):
        folder_sql = literal(IMPORT, "INSERT INTO folders(id,user_id,name,created_at,updated_at) SELECT")
        cipher_sql = literal(IMPORT, "INSERT INTO ciphers(id,user_id,organization_id,cipher_type,data,is_favorite,folder_id,archived_at,created_at,updated_at) SELECT")
        blob = '{"format_version":2,"data":"opaque"}'
        encoded = json.dumps({"name": "", "data": blob, "key": "wrapped"})
        with self.db:
            self.db.execute(folder_sql, (json.dumps([["import-folder", "encrypted-name"]]), "alice", NOW))
            self.db.execute(cipher_sql, (json.dumps([["import-cipher", 8, encoded, True, "import-folder", NOW]]), "alice", NOW))
            self.db.execute(VAULT_REVISION, (NOW, "alice")).fetchall()
        row = self.db.execute("SELECT * FROM ciphers WHERE id='import-cipher'").fetchone()
        self.assertEqual((row["cipher_type"], row["folder_id"], row["archived_at"]), (8, "import-folder", NOW))
        self.assertEqual(json.loads(row["data"])["data"], blob)

    def test_large_escaped_import_raw_column_fallback_stays_below_bind_count_limit(self):
        sql = literal(IMPORT, "INSERT INTO ciphers(id,user_id,organization_id,cipher_type,data,is_favorite,folder_id,archived_at,created_at,updated_at) VALUES")
        data = json.dumps({"name": '"' * 600_000, "login": {}})
        self.assertLess(len(data), 2_000_000)
        self.assertGreater(len(json.dumps(data)), 1_900_000)
        self.db.execute(sql, ("large", 1, data, False, None, None, "alice", NOW))
        self.assertEqual(self.db.execute("SELECT data FROM ciphers WHERE id='large'").fetchone()[0], data)

    def test_revision_failure_rolls_back_folder_cipher_and_fk_changes(self):
        self.db.execute("INSERT INTO folders(id,user_id,name,created_at,updated_at) VALUES('folder','alice','encrypted',?,?)", (OLD, OLD))
        self.db.execute("UPDATE ciphers SET folder_id='folder' WHERE id='cipher'")
        self.db.commit()
        self.db.execute("CREATE TRIGGER reject_cursor BEFORE UPDATE OF updated_at ON users BEGIN SELECT RAISE(ABORT,'cursor rejected'); END")
        with self.assertRaises(sqlite3.IntegrityError), self.db:
            self.db.execute("DELETE FROM folders WHERE id='folder'")
            self.db.execute("UPDATE ciphers SET data='new encrypted value' WHERE id='cipher'")
            self.db.execute(VAULT_REVISION, (NOW, "alice")).fetchall()
        self.assertEqual(self.row()["folder_id"], "folder")
        self.assertNotEqual(self.row()["data"], "new encrypted value")

    def test_real_row_read_exceeds_the_old_aggregate_ceiling_with_d1_limits(self):
        blob = json.dumps({"format_version": 2, "data": "x" * 450_000})
        data = json.dumps({"name": "", "data": blob})
        for index in range(10):
            self.db.execute("INSERT INTO ciphers(id,user_id,cipher_type,data,created_at,updated_at) VALUES(?,'alice',8,?,?,?)", (f"large-{index}", data, OLD, OLD))
        self.db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 2_000_000)
        self.db.setlimit(sqlite3.SQLITE_LIMIT_FUNCTION_ARG, 32)
        # This is the old single-value aggregation's failure boundary, not a
        # second implementation of the production response serializer.
        with self.assertRaises(sqlite3.DataError):
            self.db.execute("SELECT json_group_array(json(data)) FROM ciphers WHERE id LIKE 'large-%'").fetchone()
        page = first_page(self.db, "cipher", "list_page", ("alice", 1), include_attachments=True)
        rows = [row for row in page if row["id"].startswith("large-")]
        self.assertGreater(len(rows), 0)
        self.assertLess(len(rows), 10)
        self.assertTrue(page[-1]["page_has_more"])
        self.assertTrue(all(row["data"] == data for row in rows))

    def test_attachment_publication_adopts_only_one_staged_pointer(self):
        self.db.execute("INSERT INTO attachments_pending(id,cipher_id,file_name,file_size_bytes,encrypted_key,created_at,updated_at) VALUES('file','cipher','encrypted',7,'wrapped',?,?)", (OLD, OLD))
        self.db.commit()
        pending = dict(self.db.execute("SELECT * FROM attachments_pending WHERE id='file'").fetchone())
        predicate = literal(ATTACHMENTS, "EXISTS(SELECT 1 FROM attachments_pending WHERE")
        params = [pending[c] for c in ("id", "cipher_id", "file_name", "file_size_bytes", "encrypted_key", "created_at", "updated_at", "organization_id")]
        writes = statements("attachment", "finalize_upload")
        with self.db:
            self.db.execute(guard_sql(predicate), params).fetchall()
            self.db.execute(writes[0], ("file", "cipher", "encrypted", 7, "wrapped", OLD, NOW, None, "staged-winner"))
            self.db.execute(writes[1], ("file",))
            self.db.execute(writes[2], (NOW, "cipher", "alice"))
            self.db.execute(VAULT_REVISION, (NOW, "alice")).fetchall()
        with self.assertRaises(sqlite3.OperationalError), self.db:
            self.db.execute(guard_sql(predicate), params).fetchall()
            self.db.execute("UPDATE attachments SET storage_key='late-loser' WHERE id='file'")
        self.assertEqual(self.db.execute("SELECT storage_key FROM attachments WHERE id='file'").fetchone()[0], "staged-winner")


class AttachmentFinalizationSql(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        seed_cipher(self.db, "cipher", data='{"name":"encrypted"}')
        seed_attachment(self.db, "attachment", "cipher", pending=True, name="encrypted-name", key="wrapped-key")
        self.db.execute("INSERT INTO devices(user_id,device_id,name,device_type,session_token,created_at,updated_at) VALUES('alice','device','test',1,'session',?,?)", (OLD, OLD))
        self.owner = dict(self.db.execute("SELECT * FROM users WHERE id='alice'").fetchone())
        self.cipher = dict(self.db.execute("SELECT * FROM ciphers WHERE id='cipher'").fetchone())
        self.pending = dict(self.db.execute("SELECT * FROM attachments_pending WHERE id='attachment'").fetchone())
        self.db.commit()
        self.batch = statements("attachment", "finalize_upload")
        self.assertEqual(len(self.batch), 3)

    def finalize(self):
        insert, remove, touch_cipher = self.batch
        pending_predicate = literal("attachment", "EXISTS(SELECT 1 FROM attachments_pending WHERE")
        pending_args = [self.pending[column] for column in ("id", "cipher_id", "file_name", "file_size_bytes", "encrypted_key", "created_at", "updated_at", "organization_id")]
        with self.db:
            self.db.execute(session_sql(), ("alice", "stamp", "device", "session")).fetchall()
            self.db.execute(*key_guard(self.owner)).fetchall()
            self.db.execute(*row_guard(self.cipher)).fetchall()
            self.db.execute(guard_sql(pending_predicate), pending_args).fetchall()
            self.db.execute(insert, ("attachment", "cipher", "encrypted-name", 15, "wrapped-key", OLD, NOW, None, "staged-object"))
            self.db.execute(remove, ("attachment",))
            self.db.execute(touch_cipher, (NOW, "cipher", "alice"))
            self.db.execute(VAULT_REVISION, (NOW, "alice")).fetchall()

    def test_finalize_moves_reservation_and_updates_only_owner_revisions(self):
        self.finalize()
        row = self.db.execute("SELECT file_size_bytes, encrypted_key, created_at, updated_at FROM attachments").fetchone()
        self.assertEqual(tuple(row), (15, "wrapped-key", OLD, NOW))
        self.assertEqual(self.db.execute("SELECT storage_key FROM attachments").fetchone()[0], "staged-object")
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM attachments_pending").fetchone()[0], 0)
        self.assertEqual(self.db.execute("SELECT updated_at FROM ciphers WHERE id='cipher'").fetchone()[0], NOW)
        users = dict(self.db.execute("SELECT id, updated_at FROM users"))
        self.assertEqual(users, {"alice": NOW, "bob": OLD})

    def test_database_failure_rolls_back_metadata_reservation_and_revisions(self):
        self.db.execute("CREATE TRIGGER reject_revision BEFORE UPDATE OF updated_at ON users BEGIN SELECT RAISE(ABORT, 'injected attachment cursor failure'); END")
        self.db.commit()
        with self.assertRaisesRegex(sqlite3.IntegrityError, "injected attachment cursor failure"):
            self.finalize()
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM attachments").fetchone()[0], 0)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM attachments_pending").fetchone()[0], 1)
        self.assertEqual(self.db.execute("SELECT updated_at FROM ciphers WHERE id='cipher'").fetchone()[0], OLD)
        self.assertEqual(dict(self.db.execute("SELECT id, updated_at FROM users")), {"alice": OLD, "bob": OLD})

    def replace(self, expected, key):
        update, touch = statements("attachment", "replace_upload")
        predicate = next(value for value in source_literals("attachment")
                         if value.startswith("EXISTS(SELECT 1 FROM attachments WHERE id=?1 AND cipher_id=?2")
                         and "storage_key IS ?9" in value)
        cipher = dict(self.db.execute("SELECT * FROM ciphers WHERE id='cipher'").fetchone())
        args = [expected[column] for column in ("id", "cipher_id", "file_name", "file_size_bytes", "encrypted_key", "created_at", "updated_at", "organization_id", "storage_key")]
        with self.db:
            self.db.execute(session_sql(), ("alice", "stamp", "device", "session")).fetchall()
            self.db.execute(*key_guard(self.owner)).fetchall()
            self.db.execute(*row_guard(cipher)).fetchall()
            self.db.execute(guard_sql(predicate), args).fetchall()
            self.db.execute(update, (18, "replacement-wrapped-key", key, NOW, "attachment", "cipher"))
            self.db.execute(touch, (NOW, "cipher", "alice"))
            self.db.execute(VAULT_REVISION, (NOW, "alice")).fetchall()

    def test_failed_ready_replacement_rolls_back_pointer_and_old_file_cleanup(self):
        self.finalize()
        old = dict(self.db.execute("SELECT * FROM attachments").fetchone())
        self.db.execute("CREATE TRIGGER reject_replacement_revision BEFORE UPDATE OF updated_at ON users BEGIN SELECT RAISE(ABORT, 'injected attachment cursor failure'); END")
        self.db.commit()
        with self.assertRaisesRegex(sqlite3.IntegrityError, "injected attachment cursor failure"):
            self.replace(old, "replacement-object")
        self.assertEqual(dict(self.db.execute("SELECT * FROM attachments").fetchone()), old)
        self.assertIsNone(self.db.execute("SELECT 1 FROM storage_cleanup_jobs WHERE object_key='staged-object'").fetchone())


REVISION = statement("send", "revision_statement")


def snapshot(db, send_id="send"):
    row = db.execute("SELECT * FROM sends WHERE id=?", (send_id,)).fetchone()
    return dict(row) if row else None


def finalize_upload(db, before, size=7, staged="staged-object", owner=None):
    """Exercise the session, source and metadata SQL for Send upload."""
    owner = owner or dict(db.execute("SELECT * FROM users WHERE id=?", (before["user_id"],)).fetchone())
    db.commit()
    with db:
        db.execute(session_sql(), (before["user_id"], owner["security_stamp"], "device", "session")).fetchall()
        db.execute(*key_guard(owner)).fetchall()
        db.execute(*send_guard(before, upload=True)).fetchall()
        db.execute(statement("send", "finalize_upload_statement"), (size, staged, NOW, before["id"], before["user_id"])).fetchall()
        db.execute(REVISION, (NOW, before["user_id"])).fetchall()


def consume(db, send_id="send", stamp="access-stamp", file_id=None):
    db.commit()
    with db:
        rows = db.execute(statement("send", "consume_access"), (NOW, send_id, stamp, file_id)).fetchall()
        db.execute(statement("send", "access_count_guard")).fetchall()
        db.execute(REVISION, (NOW, "alice")).fetchall()
    return rows[0][0]


class SendTransactionsSql(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        self.db.setlimit(sqlite3.SQLITE_LIMIT_FUNCTION_ARG, 32)
        self.db.execute(statement("device", "persist_session_statement"), ("alice", "device", "browser", 2, "session", NOW))
        args = ("send", "alice", "encrypted-name", "encrypted-notes", 1, '{"fileName":"encrypted-file"}', "wrapped-key", None, None, None, 2, 0, OLD, OLD, None, FUTURE, 0, 0, "access-stamp", "file", 7, 1)
        self.db.execute(statement("send", "insert_statement"), args)
        self.db.commit()

    def test_file_pointer_cas_allows_exactly_one_winner_and_keeps_ready_file_on_loss(self):
        before = snapshot(self.db)
        finalize_upload(self.db, before, staged="winner")
        with self.assertRaises(sqlite3.OperationalError):
            finalize_upload(self.db, before, staged="loser")
        self.assertEqual(snapshot(self.db)["storage_key"], "winner")
        self.assertEqual(snapshot(self.db)["upload_state"], 0)

    def test_upload_allows_public_count_changes_but_preserves_them(self):
        finalize_upload(self.db, snapshot(self.db), staged="original")
        before = snapshot(self.db)
        consume(self.db, file_id="file")
        finalize_upload(self.db, before, staged="replacement")
        self.assertEqual(snapshot(self.db)["access_count"], 1)
        self.assertEqual(snapshot(self.db)["storage_key"], "replacement")

    def test_session_stamp_device_and_same_stamp_key_upgrade_fence_upload(self):
        for change in (
            "UPDATE users SET security_stamp='revoked' WHERE id='alice'",
            "DELETE FROM devices WHERE user_id='alice'",
            "UPDATE devices SET session_token='new-session' WHERE user_id='alice' AND device_id='device'",
            "UPDATE users SET key='v2-rewrapped-key',security_version=2 WHERE id='alice'",
        ):
            with self.subTest(change=change):
                db = sqlite3.connect(":memory:")
                try:
                    self.db.backup(db)
                    db.row_factory = sqlite3.Row
                    before, owner = snapshot(db), dict(db.execute("SELECT * FROM users WHERE id='alice'").fetchone())
                    db.execute(change)
                    with self.assertRaises(sqlite3.OperationalError):
                        finalize_upload(db, before, staged="rejected", owner=owner)
                    self.assertEqual(snapshot(db)["upload_state"], 1)
                    self.assertIsNone(snapshot(db)["storage_key"])
                finally:
                    db.close()

    def test_send_upload_rechecks_file_metadata_and_wrapped_key(self):
        before = snapshot(self.db)
        for column, value in (("user_id", "bob"), ("file_id", "wrong-file"), ("encrypted_key", "rotated-key")):
            with self.db:
                self.db.execute(f"UPDATE sends SET {column}=? WHERE id='send'", (value,))
                with self.assertRaises(sqlite3.OperationalError):
                    self.db.execute(*send_guard(before, upload=True))
                self.db.execute(f"UPDATE sends SET {column}=? WHERE id='send'", (before[column],))

    def test_count_and_owner_revision_roll_back_together(self):
        finalize_upload(self.db, snapshot(self.db))
        before = snapshot(self.db)
        self.db.executescript("CREATE TRIGGER fail_revision BEFORE UPDATE OF updated_at ON users BEGIN SELECT RAISE(ABORT,'revision failed'); END;")
        with self.assertRaises(sqlite3.IntegrityError):
            consume(self.db, file_id="file")
        self.assertEqual(snapshot(self.db), before)

    def test_wrong_file_id_never_consumes_and_max_is_atomic(self):
        finalize_upload(self.db, snapshot(self.db))
        with self.assertRaises(sqlite3.OperationalError):
            consume(self.db, file_id="wrong-file")
        self.assertEqual(snapshot(self.db)["access_count"], 0)
        self.assertEqual(consume(self.db, file_id="file"), 1)
        self.assertEqual(consume(self.db, file_id="file"), 2)
        with self.assertRaises(sqlite3.OperationalError):
            consume(self.db, file_id="file")
        self.assertEqual(snapshot(self.db)["access_count"], 2)

    def test_five_concurrent_text_reads_with_max_two_commit_only_two(self):
        self.db.execute("UPDATE sends SET send_type=0,upload_state=0,file_id=NULL,file_size_bytes=0")
        self.db.commit()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "send.sqlite"
            target = sqlite3.connect(path)
            self.db.backup(target)
            target.close()
            barrier = Barrier(5)
            def access(_):
                db = sqlite3.connect(path, timeout=10)
                try:
                    barrier.wait(timeout=10)
                    try:
                        consume(db)
                        return True
                    except sqlite3.OperationalError as error:
                        if "RAY_SEND_ACCESS_DENIED" not in str(error):
                            raise
                        return False
                finally:
                    db.close()
            with ThreadPoolExecutor(max_workers=5) as pool:
                self.assertEqual(sum(pool.map(access, range(5))), 2)
            target = sqlite3.connect(path)
            try:
                self.assertEqual(target.execute("SELECT access_count FROM sends").fetchone()[0], 2)
            finally:
                target.close()

    def test_rotation_changes_only_wrapped_key_revision_and_internal_revocation_stamp(self):
        finalize_upload(self.db, snapshot(self.db))
        before = snapshot(self.db)
        self.db.execute("UPDATE users SET account_write_token='rotation' WHERE id='alice'")
        self.db.execute(statement("send", "rotation_statement"), ("new-wrapped-key", NOW, "send", "alice", "rotation", "new-access-stamp"))
        after = snapshot(self.db)
        for column in before:
            if column not in ("encrypted_key", "updated_at", "access_stamp"):
                self.assertEqual(after[column], before[column], column)
        self.assertEqual(after["encrypted_key"], "new-wrapped-key")
        self.db.execute(statement("send", "rotation_statement"), ("must-not-commit", FUTURE, "send", "alice", "wrong-token", "bad"))
        self.assertEqual(snapshot(self.db), after)

    def test_rotation_guards_large_collection_without_aggregate_or_large_binds(self):
        self.db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 2_000_000)
        original = snapshot(self.db)
        self.db.execute("DELETE FROM sends")
        columns = list(original)
        insert = f"INSERT INTO sends({','.join(columns)}) VALUES({','.join('?' for _ in columns)})"
        for index in range(5):
            item = dict(original, id=f"large-{index}", send_type=0, file_id=None,
                        file_size_bytes=0, upload_state=0, data=json.dumps({"text": "a" * 450_000}))
            self.db.execute(insert, [item[column] for column in columns])
        self.db.commit()
        rows = [dict(row) for row in self.db.execute("SELECT * FROM sends ORDER BY id")]
        self.assertGreater(len(json.dumps(rows).encode()), 2_000_000)
        # This is precisely the old single-value failure; individual rows fit.
        with self.assertRaises(sqlite3.DataError):
            self.db.execute("SELECT json_group_array(json_object('id',id,'data',data)) FROM sends").fetchone()
        count_predicate = literal("send_mutation", "(SELECT COUNT", "collection_guard")
        def guards():
            self.db.execute(guard_sql(count_predicate), ("alice", len(rows))).fetchall()
            for item in rows:
                query, params = send_guard(item)
                self.assertLessEqual(len(params), 100)
                self.assertTrue(all(not isinstance(value, str) or len(value.encode()) < 2_000_000 for value in params))
                self.db.execute(query, params).fetchall()
        with self.db:
            guards()
        self.db.execute("UPDATE sends SET data='same-revision-change' WHERE id='large-0'")
        self.db.commit()
        with self.assertRaises(sqlite3.OperationalError):
            with self.db:
                guards()
        self.db.execute("UPDATE sends SET data=? WHERE id='large-0'", (rows[0]["data"],))
        added = dict(rows[0], id="concurrent-new-send")
        self.db.execute(insert, [added[column] for column in columns])
        self.db.commit()
        with self.assertRaises(sqlite3.OperationalError):
            with self.db:
                guards()

    def test_delete_sql_failure_preserves_pointer_and_cleanup_outbox_is_transactional(self):
        finalize_upload(self.db, snapshot(self.db), staged="retained")
        self.db.executescript("CREATE TRIGGER fail_delete BEFORE DELETE ON sends BEGIN SELECT RAISE(ABORT,'delete failed'); END;")
        with self.assertRaises(sqlite3.IntegrityError):
            with self.db:
                self.db.execute(statement("send", "delete_statement"), ("send", "alice"))
        self.assertEqual(snapshot(self.db)["storage_key"], "retained")
        self.assertIsNone(self.db.execute("SELECT object_key FROM storage_cleanup_jobs WHERE object_key='retained'").fetchone())


class StorageCleanupSql(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        self.db.execute("PRAGMA foreign_keys=ON")
        apply_migrations(self.db)
        self.db.execute("INSERT INTO users(id,email,master_password_hash,key,private_key,public_key,created_at,updated_at) VALUES('u','owner@example.test','hash','key','private','public','old','old')")
        self.db.execute("INSERT INTO ciphers(id,user_id,cipher_type,data,created_at,updated_at) VALUES('c','u',1,'{}','old','old')")
        self.db.execute("INSERT INTO attachments(id,cipher_id,file_name,file_size_bytes,created_at,updated_at) VALUES('a','c','encrypted',5,'old','old')")
        self.db.execute("INSERT INTO sends(id,user_id,name,send_type,data,encrypted_key,created_at,updated_at,deletes_at,access_stamp,file_id) VALUES('s','u','encrypted',1,'{}','key','old','old','future','stamp','f')")
        self.enqueue = statement("storage_cleanup", "enqueue_if_unreferenced")
        self.select = statement("storage_cleanup", "pending_batch")
        self.ack = statement("storage_cleanup", "acknowledge_prefix")

    def test_adopted_files_are_never_discarded_after_an_ambiguous_response(self):
        for key in ['c/a', 'sends/s/f']:
            self.assertEqual(self.db.execute(self.enqueue, (key, 'now')).rowcount, 0)
        self.db.execute("UPDATE attachments SET storage_key='random-attempt' WHERE id='a'")
        self.assertEqual(self.db.execute(self.enqueue, ('random-attempt', 'now')).rowcount, 0)
        self.assertEqual(self.db.execute(self.enqueue, ('failed-attempt', 'now')).rowcount, 1)
        self.assertIn('failed-attempt', {r[0] for r in self.db.execute(self.select)})

    def test_replacements_queue_only_the_previous_object(self):
        self.db.execute("UPDATE attachments SET storage_key='a-new' WHERE id='a'")
        self.db.execute("UPDATE sends SET storage_key='s-new' WHERE id='s'")
        self.assertEqual({r[0] for r in self.db.execute(self.select)}, {'c/a', 'sends/s/f'})
        self.db.execute("UPDATE attachments SET storage_key='a-new' WHERE id='a'")
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM storage_cleanup_jobs").fetchone()[0], 2)

    def test_account_cascade_retains_jobs_without_an_account_foreign_key(self):
        self.db.execute("INSERT INTO attachments_pending(id,cipher_id,file_name,file_size_bytes,created_at,updated_at) VALUES('p','c','pending',7,'old','old')")
        self.db.execute("DELETE FROM users WHERE id='u'")
        self.assertEqual({r[0] for r in self.db.execute(self.select)}, {'c/a', 'c/p', 'sends/s/f'})
        self.assertEqual(self.db.execute('PRAGMA foreign_key_check').fetchall(), [])

    def test_finalized_legacy_object_is_protected_from_pending_delete_job(self):
        self.db.execute("INSERT INTO attachments_pending(id,cipher_id,file_name,file_size_bytes,created_at,updated_at) VALUES('a','c','pending',5,'old','old')")
        self.db.execute("DELETE FROM attachments_pending WHERE id='a'")
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM storage_cleanup_jobs").fetchone()[0], 1)
        self.assertEqual(self.db.execute(self.select).fetchall(), [])

    def test_acknowledgement_cannot_remove_a_new_generation_of_the_job(self):
        self.db.execute(self.enqueue, ('failed-attempt', 'now'))
        key, generation = self.db.execute(self.select).fetchone()
        self.db.execute(self.enqueue, ('failed-attempt', 'now'))
        snapshot = json.dumps([{'object_key': key, 'generation': generation}])
        self.assertEqual(self.db.execute(self.ack, (snapshot,)).rowcount, 0)
        current = self.db.execute(self.select).fetchone()
        self.assertNotEqual(current[1], generation)
        self.assertEqual(self.db.execute(self.ack, (json.dumps([{'object_key': current[0], 'generation': current[1]}]),)).rowcount, 1)

    def test_reference_queries_use_effective_and_staged_object_key_indexes(self):
        def plan(sql, args=()):
            return "\n".join(row[3] for row in self.db.execute("EXPLAIN QUERY PLAN " + sql, args))

        for details in (plan(self.select), plan(self.enqueue, ("stage-key", "now"))):
            for table in ("attachments", "sends"):
                self.assertIn(f"idx_{table}_effective_object_key", details)
                self.assertNotIn(f"SCAN {table}", details)
        trigger = self.db.execute("SELECT sql FROM sqlite_schema WHERE name='storage_upload_stages_delete_cleanup'").fetchone()[0]
        for table in ("attachments", "sends"):
            probe = f"SELECT 1 FROM {table} WHERE storage_key = OLD.object_key"
            self.assertIn(probe, trigger)
            self.assertIn(f"idx_{table}_storage_key", plan(probe.replace("OLD.object_key", "?"), ("stage-key",)))


class UsageSql(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        # The previous nine UNION branches exceeded the actual Worker limit.
        self.db.setlimit(sqlite3.SQLITE_LIMIT_COMPOUND_SELECT, 5)
        body = extract_function((ROOT / "src/models/usage.rs").read_text(), "for_user")
        self.query = next(text for text in rust_strings(body) if text.startswith("WITH usage("))

    def test_all_usage_categories_work_without_a_large_compound_select(self):
        text = '{"name":"€🙂"}'
        seed_cipher(self.db, "utf8", "alice", data=text)
        rows = dict(self.db.execute(self.query, ("alice",)))
        self.assertEqual(len(rows), 9)
        self.assertEqual(rows["ciphers"], len(text.encode("utf-8")))
        self.assertEqual(rows["attachmentFiles"], 0)
        self.assertEqual(rows["sendFiles"], 0)

    def test_other_owners_payloads_cannot_increase_personal_usage(self):
        before = dict(self.db.execute(self.query, ("alice",)))
        seed_cipher(self.db, "other-utf8", "bob", data='{"name":"other data"}')
        self.db.execute("INSERT INTO folders(id,user_id,name,created_at,updated_at) VALUES('other-folder','bob','long folder name','old','old')")
        self.assertEqual(dict(self.db.execute(self.query, ("alice",))), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
