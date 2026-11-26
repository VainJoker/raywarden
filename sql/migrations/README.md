# D1 migrations and database design

This directory is the authoritative runtime schema. The CREATE migrations
`0001` through `0008` directly define the canonical schema for personal vaults,
small private groups, and staged object writes. New databases apply the full
chain. Existing instances with older schemas or migration histories need a
separately planned transfer to a new database. Editing baseline files does not
upgrade an application database; do not overwrite existing tables or rewrite
`d1_migrations` records.

Migration filenames follow `NNNN_<scope>_<subject>.sql`: a four-digit
execution order followed by two lowercase snake_case words describing the contents.
The same rule applies to all migration files:

| File | Tables and responsibility |
| --- | --- |
| `0001_user_accounts.sql` | Account identity, server password cost, client KDF, V1/V2 envelopes and write guards |
| `0002_access_credentials.sql` | Devices, approval requests, API keys and device-bound API-key grants |
| `0003_authentication_methods.sql` | Second factors, passkeys and single-use WebAuthn challenges |
| `0004_verification_records.sql` | Email/action verification codes and redeemed Turnstile hashes |
| `0005_personal_vault.sql` | Folders, ciphers, ownership invariants, attachment metadata and upload reservations |
| `0006_encrypted_sends.sql` | Encrypted Text/File Sends, access policy, object pointers and upload state |
| `0007_object_storage.sql` | Write staging, durable cleanup outbox and cross-table file lifecycle triggers |
| `0008_instance_state.sql` | Persistent JWT keys and shared equivalent-domain dataset/refresh lease |

Each table is declared once with canonical names, including V2 account fields,
snapshots, object pointers and verifier costs. This consolidated baseline creates
new tables; it supplies no conversion of older schemas or encrypted payloads.
There is no single-user constraint.
Files follow dependency order. Storage triggers are declared only after both
vault and Send tables exist. Each table's indexes live with its declaration.
The current schema has 20 tables and 54 explicit DDL objects. Runtime initialization, rather than migrations, populates signing keys
and the shared domain cache. Migrations create no accounts or client keys.

For Rust type roles, shared domain terms, and explicit wire mappings, see the
[project naming policy](../../docs/naming-conventions.md).

## Persisted naming and baseline compatibility

Persisted Rust fields use the same lowercase snake_case names as SQL columns.
Protocol request/response names remain independent, so the public JSON contract
continues to use fields such as `type`, `favorite`, `key` and `emailVerified`.
The factor table is `two_factors`; its provider and replay fields are
`provider_type`, `is_enabled` and `last_used_step`. The latter is a TOTP step,
not a timestamp. File metadata uses `encrypted_key` and `file_size_bytes`.
Send records use `send_type`, `expires_at`, `deletes_at`, `is_disabled`,
`is_email_hidden` and `password_iterations`. Their `upload_state` retains all
three integer states (0, 1 and 2); it is not a boolean. Device and approval fields
use `device_id`, `device_type`, `push_id`, `request_device_id`, `created_at`,
`responded_at` and `authenticated_at`. Cipher rows use `cipher_type` and
`is_favorite`; users use `is_email_verified` and `two_factor_recovery_code`.

Named indexes use `idx_<table>_<columns>` names directly in the CREATE files.
The canonical schema retains primary/unique keys, composite device-session
foreign keys, ownership constraints and file-cleanup triggers. Regression checks
exercise these rules and schema-snapshot parity on the full chain.

Wrangler records migration filenames in `d1_migrations`. Renaming a baseline
file does not rename an existing history entry, even when its numeric prefix is
unchanged; the renamed CREATE file may appear unapplied. Existing instances need
a fresh destination database and an explicit transfer plan. Do not replay these
files over existing tables or rewrite history to mark them applied. Deploy
matching code after the destination is ready; see the
[upgrade and rollback boundary](../../docs/naming-conventions.md#upgrade-and-rollback-boundary).

## Account and ownership model

Accounts have independent vaults, devices, factors, API keys, domains and Sends.
`users.email` has case-insensitive uniqueness; different allowed emails may
register concurrently, while duplicate-email races produce a conflict. There
is no global account limit or administrator/organization subsystem. Private
enrollment requires both an exact `ALLOWED_EMAILS` entry and `OWNER_SETUP_TOKEN`
authorization. Commas and newlines separate addresses; wildcards, malformed and
empty entries are rejected. The normalized list is sorted and deduplicated.
Short-lived setup cookies bind to DOMAIN and the hash of the current list, so
changing the list invalidates their scope. Registration clears the browser's
cookie; visit `/setup` again for another account. Existing accounts continue to
log in after whitelist changes. Email changes use the same exact whitelist.

Every cipher requires an account owner. Foreign keys cascade account-owned
records on deletion; indexes cover the referencing columns and per-user vault
reads. Cipher triggers enforce that a folder belongs to the same account,
including changes to either reference; folder ownership cannot be reassigned.
Deleting a folder retains its ciphers and sets their folder to NULL. The API's
user/session/snapshot guards remain necessary for authorization and concurrency.
Supported cipher types and boolean/file-size fields have basic CHECK constraints.
Opaque encrypted payloads remain in their existing protocol representation.

## Index and storage decisions

Per-account folder/cipher indexes avoid scanning other vaults during sync,
usage calculation and cascading deletion. WebAuthn's existing unique
`(user_id, credential_use, slot)` index already covers user lookups, so a duplicate
user-only index is unnecessary. Verification codes and challenges have user
indexes for account deletion. Expiry indexes use `julianday(...)` where production
queries compare timestamp instants, preserving time-zone semantics while making
those queries indexable. The Send pending-upload index is partial. Cleanup jobs
are ordered by `(created_at, object_key)` for bounded retry batches.

Attachment and Send bytes remain in object storage; D1 holds metadata and the
committed storage pointer. Deletion/replacement triggers queue old objects in a
durable outbox. The outbox deliberately has no account FK so cascades cannot
erase cleanup work. Its generation token protects retry acknowledgement from
concurrent replacement. Unfinished attachment uploads remain separate reservations
because finalization, quota accounting and expiry have different lifecycles.
Temporary object keys are registered before storage writes. Publication removes
the key's staging record in the same transaction as adopting the object pointer.
Maintenance queues expired staging keys for deletion after a one-day lease.

Server password verification defaults to 600000 iterations, independently of
client KDF settings. Credential writes record their actual cost and preserve
higher costs. Explicit lower-cost/raw verifier records remain readable by the
existing guarded login-upgrade code; no historical data rewrite runs at baseline.
JWT keys survive account deletion and must be preserved with KEY_ENCRYPTION_KEY
in any backup. Global-domain caches are rebuildable.

## Commands and future changes

```bash
just schema               # Generate a local sql/schema.sql reference.
just test-sql             # Exercise model queries and verify snapshot parity.
just test-d1              # Verify fresh migrations and file lifecycle with native D1/R2.
just db-migrate local     # Apply with Wrangler to the selected local database.
just dev                  # Apply pending local migrations before serving.
```

`just schema` generates `sql/schema.sql` from the migrations for local review.
Use Wrangler migrations for application databases and leave migration history
to Wrangler. The CREATE statements omit IF NOT EXISTS so mistakes fail.
Local commands select `env.local` in `wrangler.jsonc` and persist to
`.wrangler/local`. Remote migration requires the explicit
`just db-migrate production` target.

After this consolidation, preserve applied filenames and contents, then append `0009_*.sql`
and later for future changes. Check fresh databases
and any supported upgrade from the preceding schema. Existing instances with
older schemas need a separately planned transfer; this change does not clear,
upgrade or deploy them.
