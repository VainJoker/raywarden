"""Run production Send/guard SQL against SQLite; no network or fake D1 policy."""
from concurrent.futures import ThreadPoolExecutor
import json
import sqlite3
import tempfile
from pathlib import Path
from threading import Barrier
import unittest

from sql_fixtures import NOW, OLD, FUTURE, database, guard_sql, key_guard, send_guard, session_sql
from sql_source import literal, statement

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


class SendTransactionsSql(unittest.TestCase):
    def setUp(self):
        self.db = database()
        self.db.setlimit(sqlite3.SQLITE_LIMIT_FUNCTION_ARG, 32)
        self.addCleanup(self.db.close)
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
