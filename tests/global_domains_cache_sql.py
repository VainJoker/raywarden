"""Exercise the runtime domain cache's actual SQL without network or bindings."""
import json
import sqlite3
import unittest

from sql_fixtures import apply_migrations
from sql_source import statement, statements


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
