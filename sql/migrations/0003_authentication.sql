-- Device sessions and supported authentication methods.
-- API-key sessions reference the device session created in this file.

-- Device-bound login sessions and push registration.
CREATE TABLE devices (
    user_id TEXT NOT NULL,
    identifier TEXT NOT NULL,
    name TEXT NOT NULL,
    type INTEGER NOT NULL,
    session_token TEXT NOT NULL,
    push_token TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    push_uuid TEXT,
    PRIMARY KEY (user_id, identifier),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX idx_devices_push_uuid ON devices(push_uuid) WHERE push_uuid IS NOT NULL;

-- Login requests approved by an existing authenticated device.
CREATE TABLE auth_requests (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    request_device_identifier TEXT NOT NULL,
    device_type INTEGER NOT NULL,
    request_ip TEXT NOT NULL,
    access_code TEXT NOT NULL,
    public_key TEXT NOT NULL,
    security_stamp TEXT NOT NULL,
    enc_key TEXT,
    master_password_hash TEXT,
    approved INTEGER,
    creation_date TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    response_date TEXT,
    authentication_date TEXT,
    response_device_id TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_auth_requests_user_expiry ON auth_requests(user_id, expires_at);

-- Second-factor providers and remembered-device credentials.
CREATE TABLE twofactor (
    uuid TEXT PRIMARY KEY NOT NULL,
    user_uuid TEXT NOT NULL,
    atype INTEGER NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    data TEXT NOT NULL,
    last_used INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (user_uuid) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(user_uuid, atype)
);

-- WebAuthn credentials for Passkey login or second-factor authentication.
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
    UNIQUE(user_id, credential_use, slot),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_webauthn_credentials_user ON webauthn_credentials(user_id);

-- Single-use WebAuthn ceremony challenges.
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
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_webauthn_challenges_expiry ON webauthn_challenges(expires_at);

-- Encrypted personal API keys and their verification hashes.
CREATE TABLE user_api_keys (
    user_id TEXT PRIMARY KEY NOT NULL,
    encrypted_key TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- API-key grants bound to their current device session.
CREATE TABLE user_api_key_sessions (
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    session_token TEXT NOT NULL,
    PRIMARY KEY(user_id,device_id),
    FOREIGN KEY(user_id,device_id) REFERENCES devices(user_id,identifier) ON DELETE CASCADE
);
