-- Short-lived email/action verification and Turnstile replay protection.
-- Verification codes and redeemed Turnstile tokens are stored as hashes.

CREATE TABLE verification_codes (
    id TEXT PRIMARY KEY NOT NULL,
    owner_key TEXT NOT NULL,
    user_id TEXT,
    purpose TEXT NOT NULL,
    recipient TEXT NOT NULL,
    context TEXT NOT NULL DEFAULT '',
    code_hash TEXT NOT NULL,
    security_stamp TEXT NOT NULL DEFAULT '',
    session_token TEXT NOT NULL DEFAULT '',
    attempts INTEGER NOT NULL DEFAULT 0,
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    ready INTEGER NOT NULL DEFAULT 0,
    consumed_at INTEGER,
    UNIQUE(owner_key, purpose, recipient, context),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_verification_codes_expiry ON verification_codes(expires_at);

CREATE TABLE turnstile_redemptions (
    token_hash TEXT PRIMARY KEY NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE INDEX idx_turnstile_redemptions_expiry ON turnstile_redemptions(expires_at);
