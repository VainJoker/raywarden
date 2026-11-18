-- V2 account envelopes and exact-generation guards for encrypted writes.
ALTER TABLE users ADD COLUMN signed_public_key TEXT;
ALTER TABLE users ADD COLUMN security_state TEXT;
ALTER TABLE users ADD COLUMN security_version INTEGER;
ALTER TABLE users ADD COLUMN signature_key_pair TEXT;
ALTER TABLE users ADD COLUMN v2_upgrade_token TEXT;
ALTER TABLE users ADD COLUMN security_stamp_exceptions TEXT;
ALTER TABLE users ADD COLUMN account_write_token TEXT;
ALTER TABLE auth_requests ADD COLUMN account_snapshot TEXT;
ALTER TABLE webauthn_credentials ADD COLUMN account_snapshot TEXT;
ALTER TABLE webauthn_challenges ADD COLUMN account_snapshot TEXT;
-- Existing PRF envelopes belong to the account generation present at migration.
UPDATE webauthn_credentials SET account_snapshot=(
    SELECT json_object('key',key,'user_key_id',user_key_id,'private_key',private_key,
        'public_key',public_key,'signed_public_key',signed_public_key,
        'security_state',security_state,'security_version',security_version,
        'signature_key_pair',signature_key_pair)
    FROM users WHERE users.id=webauthn_credentials.user_id
) WHERE encrypted_user_key IS NOT NULL;
