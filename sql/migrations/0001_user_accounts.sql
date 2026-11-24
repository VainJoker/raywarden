-- Account identity, password verification costs, client KDF and V1/V2 key envelopes.
CREATE TABLE users (
    id TEXT PRIMARY KEY NOT NULL,
    email TEXT NOT NULL COLLATE NOCASE UNIQUE,
    is_email_verified BOOLEAN NOT NULL DEFAULT 0 CHECK (is_email_verified IN (0, 1)),
    name TEXT,
    avatar_color TEXT,

    -- Server verifier cost is separate from the client's key-derivation settings.
    master_password_hash TEXT NOT NULL,
    password_salt TEXT,
    password_iterations INTEGER NOT NULL DEFAULT 600000
        CHECK (typeof(password_iterations) = 'integer'
            AND password_iterations > 0 AND password_iterations <= 4294967295),
    master_password_hint TEXT,
    kdf_type INTEGER NOT NULL DEFAULT 0,
    kdf_iterations INTEGER NOT NULL DEFAULT 600000,
    kdf_memory INTEGER,
    kdf_parallelism INTEGER,

    key TEXT NOT NULL,
    private_key TEXT NOT NULL,
    public_key TEXT NOT NULL,
    user_key_id TEXT,
    signed_public_key TEXT,
    security_state TEXT,
    security_version INTEGER,
    signature_key_pair TEXT,
    v2_upgrade_token TEXT,
    security_stamp TEXT,
    security_stamp_exceptions TEXT,
    account_write_token TEXT,
    two_factor_recovery_code TEXT,

    equivalent_domains TEXT NOT NULL DEFAULT '[]',
    excluded_globals TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
