"""Execute the production personal-vault transaction SQL in in-memory SQLite."""
import json
import sqlite3
import unittest

from sql_fixtures import NOW, OLD, VAULT_REVISION, database, first_page, guard_sql, key_guard, row_guard, session_sql
from sql_source import literal, statements

CIPHERS = "cipher_writes"
IMPORT = "vault_import"
ATTACHMENTS = "attachment"


class CipherTransactions(unittest.TestCase):
    def setUp(self):
        self.db = database()
        self.addCleanup(self.db.close)
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


if __name__ == "__main__":
    unittest.main()
