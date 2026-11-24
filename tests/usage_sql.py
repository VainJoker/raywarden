"""Logical usage stays valid under workerd's bounded compound-SELECT limit."""
import sqlite3
import unittest

from sql_fixtures import database, seed_cipher
from sql_source import ROOT, extract_function, rust_strings


class UsageSql(unittest.TestCase):
    def setUp(self):
        self.db = database()
        self.addCleanup(self.db.close)
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
