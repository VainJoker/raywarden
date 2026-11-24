"""Shared SQLite data and setup for model SQL tests."""
import json
import re
import sqlite3

from sql_source import ROOT, account_guard, function_source, literal, rust_strings, source, source_literals, statement

NOW = "2026-11-13T03:00:00.000Z"
OLD = "2020-01-01T00:00:00.000Z"
FUTURE = "2026-11-14T03:00:00.000Z"
VAULT_REVISION = statement("cipher_mutation", "commit")


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


def guard_sql(predicate):
    return statement("cipher_mutation", "guard").replace("{predicate}", predicate)


def send_guard(snapshot, upload=False):
    if upload:
        predicate = next(text for text in source_literals("send", "upload_predicate") if text.startswith("EXISTS("))
        args = [snapshot[column] for column in (
            "id", "user_id", "data", "encrypted_key", "file_id", "file_size_bytes", "storage_key", "upload_state"
        )]
    else:
        columns = source_literals("send", "snapshot_columns")
        source = source_literals("send", "snapshot_predicate")
        column_template = next(text for text in source if "{column}" in text)
        predicate = next(text for text in source if text.startswith("EXISTS("))
        predicate = predicate.replace("{predicate}", " AND ".join(column_template.replace("{column}", column).replace("{}", str(index + 1)) for index, column in enumerate(columns)))
        args = [snapshot[column] for column in columns]
    return guard_sql(predicate), args


def session_sql():
    return statement("cipher_mutation", "commit_session")


def key_guard(snapshot):
    exists = literal("cipher_mutation", "EXISTS(", "account_snapshot_guard")
    return guard_sql(exists.replace("{}", account_guard(2))), [snapshot["id"], json.dumps(snapshot)]


def row_guard(row):
    predicate = literal("cipher_mutation", "EXISTS(SELECT 1 FROM ciphers WHERE id=")
    columns = ("id", "user_id", "organization_id", "cipher_type", "data", "is_favorite", "folder_id", "deleted_at", "archived_at", "created_at", "updated_at")
    return guard_sql(predicate), [row[column] for column in columns]



def first_page(db, model, spec_name, filter_params, *, include_attachments=False):
    """Exercise one bounded SQL page; Worker tests drive the keyset traversal."""
    page = function_source("read_page", "sql")
    rowid_order = page.split("PageOrder::RowId =>", 1)[1].split("PageOrder::", 1)[0]
    date, after, ordering = rust_strings(rowid_order)
    size_template = literal("read_page", "COALESCE(length", "sql")
    template = literal("read_page", "WITH filtered", "sql")
    if model == "attachment":
        table, *columns = source_literals(model, "paged")
        predicate = literal(model, "cipher_id IN", spec_name)
    else:
        table, predicate, *columns = source_literals(model, spec_name)
    count = int(re.search(r"const PAGE_ROWS: u32 = ([0-9_]+)", source("read_page"))[1])
    budget = int(re.search(r"const PAGE_BYTES: u32 = ([0-9_]+)", source("read_page"))[1])
    related = literal("cipher", "SELECT COALESCE(SUM(") if include_attachments else "0"
    query = template.format(
        table=table, filter=predicate, date=date, after=after, ordering=ordering,
        related=related, lookahead=count + 1,
        size="+".join(size_template.format(column=column) for column in columns),
    )
    return db.execute(query, (*filter_params, None, None, count + 1, budget)).fetchall()
