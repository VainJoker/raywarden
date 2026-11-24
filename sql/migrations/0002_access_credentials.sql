-- Device sessions, device approval requests and personal API-key grants.

CREATE TABLE devices (
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    name TEXT NOT NULL,
    device_type INTEGER NOT NULL,
    session_token TEXT NOT NULL,
    push_token TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    push_id TEXT,
    PRIMARY KEY (user_id, device_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE auth_requests (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    request_device_id TEXT NOT NULL,
    device_type INTEGER NOT NULL,
    request_ip TEXT NOT NULL,
    access_code TEXT NOT NULL,
    public_key TEXT NOT NULL,
    security_stamp TEXT NOT NULL,
    encrypted_key TEXT,
    master_password_hash TEXT,
    approved INTEGER,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    responded_at TEXT,
    authenticated_at TEXT,
    response_device_id TEXT,
    account_snapshot TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE user_api_keys (
    user_id TEXT PRIMARY KEY NOT NULL,
    encrypted_key TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE user_api_key_sessions (
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    session_token TEXT NOT NULL,
    PRIMARY KEY(user_id,device_id),
    FOREIGN KEY(user_id,device_id) REFERENCES devices(user_id,device_id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX idx_devices_push_id ON devices(push_id) WHERE push_id IS NOT NULL;

CREATE INDEX idx_auth_requests_user_id_expires_at ON auth_requests(user_id, julianday(expires_at));

CREATE INDEX idx_auth_requests_expires_at ON auth_requests(julianday(expires_at));
