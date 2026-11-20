"""Date predicates compare old RFC3339 offsets by instant, without rewriting rows."""
import unittest

from sql_regression import seed_cipher, seed_attachment

from sql_regression import account_snapshot, database, statement, trash_purge_statements

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


class StoredTimestampSql(unittest.TestCase):
    def setUp(self):
        self.db = database()
        self.addCleanup(self.db.close)

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
        touch, delete = trash_purge_statements()
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
