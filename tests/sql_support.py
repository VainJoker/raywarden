"""Production SQL extraction and disposable SQLite fixtures."""

from functools import lru_cache
from pathlib import Path
import json
import re
import sqlite3
import unittest

ROOT = Path(__file__).resolve().parents[1]


SOURCES = {
    "account_keys": "src/models/identity/account_keys.rs",
    "api_key": "src/models/identity/api_key.rs",
    "attachment": "src/models/vault/attachment.rs",
    "auth_request": "src/models/identity/auth_request.rs",
    "cipher": "src/models/vault/cipher.rs",
    "device": "src/models/identity/device.rs",
    "domains": "src/models/vault/domains.rs",
    "email": "src/models/identity/email.rs",
    "folder": "src/models/vault/folder.rs",
    "purge": "src/models/vault/cipher.rs",
    "push": "src/models/identity/push.rs",
    "send": "src/models/send.rs",
    "two_factor": "src/models/identity/two_factor.rs",
    "user": "src/models/identity/user.rs",
    "webauthn": "src/models/identity/webauthn.rs",
    "account_rotation": "src/models/identity/account_keys/rotation.rs",
    "cipher_mutation": "src/models/mutation.rs",
    "cipher_changes": "src/models/vault/cipher.rs",
    "cipher_writes": "src/models/vault/cipher.rs",
    "vault_import": "src/models/vault/import.rs",
    "jwt_keys": "src/models/identity/jwt_keys.rs",
    "storage_cleanup": "src/models/storage.rs",
    "send_mutation": "src/models/send.rs",
    "db_errors": "src/errors/database.rs",
    "read_page": "src/models/page.rs",
}


TOKENS = re.compile(
    r'(?P<line>//[^\n]*)|(?P<block>/\*.*?\*/)|'
    r'r(?P<hash>\#*)"(?P<raw>.*?)"(?P=hash)|'
    r'"(?P<string>(?:\\.|[^"\\])*)"|'
    r"(?P<char>'(?:\\(?:u\{[\da-fA-F_]+\}|x[\da-fA-F]{2}|.)|[^'\\\r\n])')",
    re.S,
)


def source(module):
    if module not in SOURCES:
        raise AssertionError(f"Unregistered SQL source: {module}")
    return (ROOT / SOURCES[module]).read_text()


def _check_comment(match):
    block = match.group("block")
    if block is not None and "/*" in block[2:]:
        raise AssertionError("Nested Rust block comments need explicit SQL-reader support")


def _code_mask(text):
    def mask(match):
        _check_comment(match)
        return re.sub(r"[^\n]", " ", match.group())
    return TOKENS.sub(mask, text)


def extract_function(text, name, location="Rust source"):
    code = _code_mask(text)
    matches = list(re.finditer(rf"\bfn\s+{re.escape(name)}\b\s*(?:<[^;{{}}]*>)?\s*\(", code))
    if len(matches) != 1:
        raise AssertionError(f"Expected one {location}::{name}, found {len(matches)}")
    start = matches[0].start()
    opening = -1
    delimiters = ["("]  # The function-name match includes the first '('.
    for index in range(matches[0].end(), len(code)):
        char = code[index]
        if char in "([":
            delimiters.append(char)
        elif char in ")]":
            delimiters.pop()
        elif not delimiters:
            if char == ";":
                break  # A declaration is not the next function's body.
            if char == "{":
                opening = index
                break
    if opening < 0:
        raise AssertionError(f"Missing function body: {location}::{name}")
    depth = 0
    for index in range(opening, len(code)):
        if code[index] == "{":
            depth += 1
        elif code[index] == "}":
            depth -= 1
            if depth == 0:
                return text[start:index + 1]
    raise AssertionError(f"Unclosed function body: {location}::{name}")


def function_source(module, name):
    return extract_function(source(module), name, SOURCES[module])


def _decode_string(text):
    """Decode Rust string escapes, including line continuations and SQL \\'."""
    escapes = {"n": "\n", "r": "\r", "t": "\t", "0": "\0", "\\": "\\", '"': '"', "'": "'"}
    result = []
    index = 0
    while index < len(text):
        char = text[index]
        index += 1
        if char != "\\":
            result.append(char)
            continue
        escape = text[index]
        index += 1
        if escape in "\r\n":
            while index < len(text) and text[index].isspace():
                index += 1
        elif escape in escapes:
            result.append(escapes[escape])
        elif escape == "x":
            result.append(chr(int(text[index:index + 2], 16)))
            index += 2
        elif escape == "u" and text[index] == "{":
            end = text.index("}", index)
            result.append(chr(int(text[index + 1:end].replace("_", ""), 16)))
            index = end + 1
        else:
            raise AssertionError(f"Unsupported Rust string escape: {escape!r}")
    return "".join(result)


def rust_strings(text):
    for match in TOKENS.finditer(text):
        _check_comment(match)
        if match.group("raw") is not None:
            yield match.group("raw")
        elif match.group("string") is not None:
            yield _decode_string(match.group("string"))


def account_guard(parameter):
    return _account_snapshot_predicate("", f"?{parameter}")


def _account_snapshot_predicate(qualifier, snapshot):
    literals = list(rust_strings(function_source("account_keys", "matches_sql_expression")))
    columns = [text for text in literals if re.fullmatch(r"[a-z_]+", text)]
    template = next(text for text in literals if "{column}" in text)
    return " AND ".join(template.format(qualifier=qualifier, column=column, snapshot=snapshot)
                        for column in columns)


def _expand_snapshot_predicate(query, body, location):
    # Resolve the one named SQL fragment shared by the account models.
    matches = re.findall(
        r"\blet snapshot_predicate\s*=\s*AccountSnapshot::"
        r"(matches_sql|matches_sql_expression)\(([^)]*)\);",
        body,
    )
    if len(matches) != 1:
        raise AssertionError(f"Expected one account snapshot predicate in {location}")
    method, args = matches[0]
    if method == "matches_sql":
        predicate = account_guard(int(args.strip()))
    else:
        qualifier, snapshot = rust_strings(args)
        predicate = _account_snapshot_predicate(qualifier, snapshot)
    return query.replace("{snapshot_predicate}", predicate)


def _expand_user_revision(query, body, location):
    if "{revision_sql}" not in query and "{NEXT_USER_REVISION_SQL}" not in query:
        return query
    revision = literal("cipher_mutation", "CASE WHEN julianday(updated_at)")
    if "{revision_sql}" in query:
        match = re.search(
            r"\blet revision_sql\s*=\s*(?:crate::models::mutation::)?"
            r"next_user_revision_sql\((\d+)\)",
            body,
        )
        if match is None:
            raise AssertionError(f"Missing user revision bind position in {location}")
        query = query.replace("{revision_sql}", revision.replace("?1", f"?{match[1]}"))
    return query.replace("{NEXT_USER_REVISION_SQL}", revision)


def _db_abort_expressions():
    text = source("db_errors")
    block = re.search(r"^db_sentinels!\s*\{(.*?)^\}", text, re.M | re.S)
    template = re.search(r"\bconcat!\([^\n]*\$value[^\n]*\)", text)
    if block is None or template is None:
        raise AssertionError("Expected DB sentinel definitions and SQL abort expression")
    prefix, suffix = rust_strings(template.group())
    return {name: prefix + marker + suffix
            for name, marker in re.findall(r'(\w+)\s*=>\s*"([A-Z_]+)"', block[1])}


def _expand_db_sentinels(query, body):
    for name, variant in re.findall(
        r"\blet\s+(\w+)\s*=\s*DbSentinel::(\w+)\.sql_abort_expr\(\);", body,
    ):
        placeholder = "{" + name + "}"
        if placeholder in query:
            query = query.replace(placeholder, _db_abort_expressions()[variant])
    return query


def statements(module, name):
    body = function_source(module, name)
    location = f"{module}::{name}"
    queries = []
    for text in rust_strings(body):
        if not re.match(r"\s*(SELECT|INSERT|UPDATE|DELETE)\b", text):
            continue
        if "{snapshot_predicate}" in text:
            text = _expand_snapshot_predicate(text, body, location)
        text = _expand_user_revision(text, body, location)
        queries.append(_expand_db_sentinels(text, body))
    return tuple(queries)


def statement(module, name):
    result = statements(module, name)
    if len(result) != 1:
        raise AssertionError(f"Expected one SQL literal in {module}::{name}, got {len(result)}")
    return result[0]


def source_literals(module, function=None):
    text = source(module) if function is None else function_source(module, function)
    return list(rust_strings(text))


def literal(module, prefix, function=None):
    matches = [text for text in source_literals(module, function) if text.startswith(prefix)]
    if len(matches) != 1:
        raise AssertionError(f"Expected one SQL prefix in {module}: {prefix!r}, found {len(matches)}")
    return matches[0]

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


class DatabaseTestCase(unittest.TestCase):
    """Start each test with a fresh migrated database and two independent users."""

    def setUp(self):
        self.db = database()
        self.addCleanup(self.db.close)
