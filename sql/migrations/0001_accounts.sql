-- Account identity, wrapped account keys and client KDF settings.

CREATE TABLE users (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT,
    email TEXT NOT NULL UNIQUE,
    email_verified BOOLEAN NOT NULL DEFAULT 0,
    master_password_hash TEXT NOT NULL,
    master_password_hint TEXT,
    key TEXT NOT NULL,
    private_key TEXT NOT NULL,
    public_key TEXT NOT NULL,
    kdf_type INTEGER NOT NULL DEFAULT 0,
    kdf_iterations INTEGER NOT NULL DEFAULT 600000,
    security_stamp TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    password_salt TEXT,
    kdf_memory INTEGER,
    kdf_parallelism INTEGER,
    totp_recover TEXT,
    avatar_color TEXT,
    equivalent_domains TEXT NOT NULL DEFAULT '[]',
    excluded_globals TEXT NOT NULL DEFAULT '[]',
    user_key_id TEXT
);
