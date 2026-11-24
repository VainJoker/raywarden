-- Second factors, passkey credentials and single-use WebAuthn challenges.

CREATE TABLE two_factors (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    provider_type INTEGER NOT NULL,
    is_enabled INTEGER NOT NULL DEFAULT 1,
    data TEXT NOT NULL,
    last_used_step INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(user_id, provider_type)
);

CREATE TABLE webauthn_credentials (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    slot INTEGER NOT NULL,
    name TEXT NOT NULL,
    credential_id TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    credential_use TEXT NOT NULL CHECK (credential_use IN ('login','2fa')),
    prf_status INTEGER NOT NULL DEFAULT 2,
    encrypted_public_key TEXT,
    encrypted_user_key TEXT,
    encrypted_private_key TEXT,
    last_challenge TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    account_snapshot TEXT,
    UNIQUE(user_id, credential_use, slot),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE webauthn_challenges (
    id TEXT PRIMARY KEY NOT NULL,
    challenge TEXT NOT NULL UNIQUE,
    purpose TEXT NOT NULL,
    user_id TEXT,
    security_stamp TEXT,
    device_id TEXT,
    session_token TEXT,
    rp_id TEXT NOT NULL,
    origin TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    account_snapshot TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_webauthn_challenges_user_id ON webauthn_challenges(user_id);

CREATE INDEX idx_webauthn_challenges_expires_at ON webauthn_challenges(julianday(expires_at));
