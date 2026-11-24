"""Locate production SQL explicitly; never substitute test-owned queries.

This small reader skips Rust strings/comments while locating a named function.
Missing or ambiguous definitions fail instead of silently taking another body.
"""
from functools import lru_cache
import re
from pathlib import Path

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

# Raw strings (including r"..."), ordinary strings, chars and comments. Lifetimes
# aren't char literals. Contents are masked before counting function braces.
TOKENS = re.compile(
    r'(?P<line>//[^\n]*)|(?P<block>/\*.*?\*/)|'
    r'r(?P<hash>\#*)"(?P<raw>.*?)"(?P=hash)|'
    r'"(?P<string>(?:\\.|[^"\\])*)"|'
    r"(?P<char>'(?:\\(?:u\{[\da-fA-F_]+\}|x[\da-fA-F]{2}|.)|[^'\\\r\n])')",
    re.S,
)


@lru_cache(maxsize=None)
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


@lru_cache(maxsize=None)
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


@lru_cache(maxsize=1)
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


@lru_cache(maxsize=None)
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
