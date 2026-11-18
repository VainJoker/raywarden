"""Locate production SQL explicitly; never substitute test-owned queries.

This small reader skips Rust strings/comments while locating a named function.
Missing or ambiguous definitions fail instead of silently taking another body.
"""
from functools import lru_cache
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCES = {
    "account_keys": "src/models/account_keys.rs",
    "api_key": "src/models/api_key.rs",
    "attachment": "src/models/attachment.rs",
    "auth_request": "src/models/auth_request.rs",
    "cipher": "src/models/cipher/store.rs",
    "device": "src/models/device.rs",
    "domains": "src/models/domains.rs",
    "email": "src/models/email.rs",
    "folder": "src/models/folder.rs",
    "purge": "src/models/purge.rs",
    "push": "src/models/push.rs",
    "send": "src/send/store.rs",
    "twofactor": "src/models/twofactor.rs",
    "user": "src/models/user/store.rs",
    "webauthn": "src/models/webauthn.rs",
    "account_rotation": "src/api/service/account_keys.rs",
    "cipher_mutation": "src/api/service/cipher_mutation.rs",
    "cipher_changes": "src/api/service/ciphers.rs",
    "cipher_http": "src/api/controller/ciphers.rs",
    "attachment_http": "src/api/controller/attachments.rs",
    "vault_import": "src/api/controller/import.rs",
    "jwt_keys": "src/infra/jwt_keys.rs",
    "storage_cleanup": "src/infra/storage/cleanup.rs",
    "send_mutation": "src/send/mutation.rs",
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


@lru_cache(maxsize=None)
def statements(module, name):
    return [text for text in rust_strings(function_source(module, name))
            if re.match(r"\s*(SELECT|INSERT|UPDATE|DELETE)\b", text)]


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
