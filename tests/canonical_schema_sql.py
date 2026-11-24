"""Exercise canonical persisted names, opaque payloads and schema safeguards."""
import json
import sqlite3
import unittest

from sql_fixtures import apply_migrations


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
