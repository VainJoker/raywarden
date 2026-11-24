# Naming conventions

This policy applies to handwritten Rust, SQL, tests, and new documentation.
Use the same business term across layers, with explicit mappings where an
external contract uses another spelling. See the [architecture](architecture.md)
for module responsibilities and the [migration guide](../sql/migrations/README.md)
for the persisted schema.

## Rust identifiers and domain roots

Use `snake_case` for modules, files, functions, methods, parameters, and fields;
`UpperCamelCase` for types, traits, and enum variants; and `SCREAMING_SNAKE_CASE`
for constants and statics. Follow established Rust spellings such as `Uuid`
rather than introducing uppercase acronym type names.

Use a singular entity name for entity modules and shared workflows: `user`,
`cipher`, `folder`, `device`, `auth_request`, `two_factor`, and `send`. An entity
root identifies its feature; it does not require that feature to sit directly
under `service` or `models`. Both layers group account and authentication
features under `identity`, and vault content features under `vault`. Keep a
feature's request types, validation, projections, and workflows within its
service module. For example, cipher workflows are in
`service/vault/cipher.rs`, folder workflows are in
`service/vault/folder.rs`, and attachment uploads are in
`service/vault/attachment/upload.rs`.

Collection concepts such as `domains`, `account_keys`, and `notifications`
retain their established meaning. Send remains a separate feature;
`service/notifications.rs` owns notification publishing, with independent
administrative delivery and mobile push capabilities. Account handlers publish
client notifications after successful changes.
Shared state, maintenance, and transaction helpers remain at the layer root
when several features use them. Controller feature files may remain plural,
such as `api/controller/identity/devices.rs`.

Use capability names where they identify what a module owns. Token exchange
and session cookies live in `identity/oauth.rs`, attempt and Send limits in
`service/rate_limit.rs`, and guarded vault writes in `service/vault_write.rs`.

Put declaration-only groups in their directory's `mod.rs`. Keep an entity's
persisted row, scalar values, queries, and write assertions together in a
substantive module such as `user.rs`, `cipher.rs`, or `send.rs`. Split a feature
when a child represents a complete capability with
its own inputs and rules, such as upload or WebAuthn. Keep a type beside its
validation or serialization rather than dividing definitions and implementations
between generic `types`, `codec`, and `store` files. File length alone does not
justify a module boundary.

Choose names for their role rather than adding the layer to every identifier.
Within a clear scope, `id`, `key`, `data`, `row`, and `payload` are valid names.
Qualify them when several values coexist: `device_id`, `encrypted_key`,
`previous`, `replacement`, or `initialization`. An encrypted key and a plaintext
key must remain distinguishable. Standard protocol terms such as the user's
wrapped `key`, a public `id`, or an opaque encrypted payload do not require
renaming merely because they are short.

## Types describe the data they hold

| Role | Naming and examples |
| --- | --- |
| Persisted record or query row | `*Row`: `UserRow`, `CipherRow`, `TwoFactorRow`, `DeviceRow` |
| Operation request | `*Request`: `RegisterRequest`, `AccountVerificationRequest`, `RotateSendRequest` |
| Nested protocol body or encrypted payload | `*Payload`: `MasterPasswordUnlockPayload`, `RotateAccountPayload`, `CipherPayload` |
| Public response | `*Response`: `PreloginResponse`, `CipherResponse`, `AttachmentResponse` |
| Material accepted after validation/normalization | `Validated*`: `ValidatedAccountKeys`, `ValidatedSetPassword` |
| A specific domain value or concurrency record | Keep its meaning: `StoredPassword`, `KdfParams`, `Claims`, `AccountSnapshot`, `SessionSnapshot` |

Persisted rows, query execution, and batch commits belong in `models` as module
functions or inherent methods on the domain row/command types, including the
`SELECT 1` health check. Resolve the D1 binding through `infra::db::binding`.
Configuration reads and parsing live in `infra/config`. Database access helpers
and storage backends belong in `infra`. Shared CORS and response header defaults
live in `api/middleware`. Request extractors, response wrappers, and Worker
response conversion live in `api/common`. Download responses live in
`api/common/download.rs`. Verification mail and administrative notifications
share JSON delivery in `service/notifications.rs`. Generic utilities such as
timestamps belong in `utils`.

Utilities express shared mechanics, such as the strict integer-boolean Serde
adapter, constant-time UTF-8 string equality, and numeric version parsing.
`utils::version::parse` returns a `ParsedVersion` struct (`major`, `minor`,
`patch`, and `is_prerelease`); it validates and discards build metadata.
Client minimum version policies remain with their callers alongside
`ParsedVersion::satisfies_minimum`.

Request/response shapes, business validation, credential policy, and workflows
belong in `service`. Service functions operate explicitly on model rows rather
than adding business methods through service-defined inherent `impl` blocks on
row types. API routes live in `api/routers`, and handlers extract requests and map
results in `api/controller`. Send HTTP adapters live in `api/controller/send.rs`,
with workflows in `service/send`. `api/edge` contains Worker edge routing and
thin Durable Object hosts over `service/notifications`.

## Fields, booleans, timestamps, and units

Rust persisted fields use the same names as their SQL columns. Boolean state
uses `is_` or `has_` when it represents a boolean, such as `is_enabled`,
`is_disabled`, `is_email_verified`, and `is_favorite`. An integer state machine
keeps a state name: Send `upload_state` preserves the values `0`, `1`, and `2`.
It must not be collapsed into `is_pending` or another boolean.

Use `*_at` for a timestamp or scheduled instant: `created_at`, `updated_at`,
`responded_at`, `authenticated_at`, `expires_at`, and `deletes_at`. Document the
representation where the type alone does not establish it. Duration and size
names carry their units, such as `duration_seconds`, `timeout_ms`, and
`file_size_bytes`. A timestamp suffix does not imply that a stored string has
become an epoch integer, or that a duration has become a timestamp.

`TwoFactorRow.last_used_step` is the last accepted TOTP counter step. It is not
an epoch timestamp and must not be renamed to `last_used_at`. The canonical
schema retains its integer representation and replay-protection rules.

These are examples from the current repository:

| Earlier persisted name | Canonical persisted name | Meaning |
| --- | --- | --- |
| `twofactor` | `two_factors` | Factor records table |
| `uuid`, `user_uuid`, `atype` on factors | `id`, `user_id`, `provider_type` | Record identity, owner, and provider discriminator |
| `enabled`, `last_used` on factors | `is_enabled`, `last_used_step` | Enabled state and accepted TOTP step |
| `akey`, `enc_key` | `encrypted_key` | Wrapped/encrypted key material in attachment, Send, or approval records |
| `file_size` | `file_size_bytes` | File length in bytes |
| `creation_date`, `response_date`, `authentication_date` on approvals | `created_at`, `responded_at`, `authenticated_at` | Approval lifecycle instants |
| `request_device_identifier` | `request_device_id` | Requesting device identity |
| `identifier`, `type`, `push_uuid` on devices | `device_id`, `device_type`, `push_id` | Device identity, client discriminator, and relay identity |
| `type`, `favorite` on ciphers | `cipher_type`, `is_favorite` | Cipher discriminator and favorite flag |
| `type`, `password_iter`, `pending` on Sends | `send_type`, `password_iterations`, `upload_state` | Send discriminator, verifier cost, and upload state |
| `expiration_date`, `deletion_date` on Sends | `expires_at`, `deletes_at` | Access expiry and scheduled deletion |
| `disabled`, `hide_email` on Sends | `is_disabled`, `is_email_hidden` | Boolean access/display policy |
| `email_verified`, `totp_recover` on users | `is_email_verified`, `two_factor_recovery_code` | Email state and recovery material |

## SQL objects and migration history

SQL tables and columns use lowercase `snake_case`. Existing entity tables use
plural domain names, such as `users`, `ciphers`, `devices`, `two_factors`, and
`sends`. Use `id` for a record's primary identity and `<entity>_id` for references
where that entity supplies the identity. Preserve existing composite identities
and meaningful established names.

Named indexes follow `idx_<table>_<indexed_columns>` in indexed-column order.
Use the underlying column name for an expression index: for example,
`idx_sends_deletes_at` indexes `julianday(deletes_at)`. A partial predicate does
not add columns to the name: `idx_sends_created_at` indexes `created_at` for rows
whose `upload_state <> 0`. The cleanup order index is
`idx_storage_cleanup_jobs_created_at_object_key`.

Migration filenames follow `NNNN_<scope>_<subject>.sql`: a four-digit
execution order followed by two lowercase snake_case words describing the contents, such as
`0001_user_accounts.sql` and `0005_personal_vault.sql`.

Canonical table, column, and index names are defined directly in the CREATE
migrations `0001` through `0008`. New databases apply the full chain in order.
This consolidated baseline is not an incremental upgrade for an existing
database. The current schema has 20 tables and 54 explicit DDL objects.

After this consolidation, preserve applied migration filenames and contents,
then append `0009_*.sql` or later for future changes. Regenerate `sql/schema.sql`
from the complete chain and verify fresh creation and any supported incremental
upgrade.

## External names are explicit contracts

Internal renames do not rename public JSON fields, HTTP routes or headers,
environment variables, JWT claims, stored protocol payloads, or Durable Object
exports. Keep existing Serde `rename`/`alias` attributes and explicit response
projections. For example:

| Internal value | Existing external name |
| --- | --- |
| Cipher `cipher_type`, `is_favorite` | JSON `type`, `favorite` |
| Send `encrypted_key`, `expires_at`, `deletes_at` | JSON `key`, `expirationDate`, `deletionDate` |
| Send `is_disabled`, `is_email_hidden` | JSON `disabled`, `hideEmail` |
| Approval `created_at`, `responded_at`, `encrypted_key` | JSON `creationDate`, `responseDate`, `key` |
| User `is_email_verified` in a profile | JSON `emailVerified` |
| Claims extension `is_email_verified`, `is_premium` | JWT `email_verified`, `premium` |
| JWT purpose, identity, and timestamp claims | Existing `token_use`, `sub`, `exp`, `nbf`, `iat`, and `sstamp` claims |
| Rust configuration access | Existing `ALLOWED_EMAILS`, `OWNER_SETUP_TOKEN`, `KEY_ENCRYPTION_KEY`, and other environment names |
| DO adapters under `api/edge/` | Bindings and exported classes use lowercase `heavydo`, `notifydo`; Cloudflare displays `raywarden_heavydo`, `raywarden_notifydo` |

The two Durable Object adapter structs intentionally use lowercase names because
`worker-rs` derives their JavaScript class exports from the Rust identifiers.
The local `non_camel_case_types` allowance applies only to these adapters.

Database-row snapshots are internal persistence contracts, so their keys follow
the canonical column names. Public DTOs and persisted protocol payloads are
mapped separately. Preserve opaque encrypted JSON and existing signed token
formats; a Rust identifier change does not authorize rewriting their contents.

## Upgrade and rollback boundary

The consolidated baseline creates a new database with canonical names. Existing
instances with older schemas or migration histories need a separately planned
transfer to a new database before running this code. Wrangler records filenames
in `d1_migrations`: renaming a file does not rename an existing entry, even when
its numeric prefix is unchanged. A renamed CREATE file may therefore appear
unapplied; this is not an upgrade path. Do not replay CREATE files over existing
tables or rewrite history to manufacture a match.

Preserve a recoverable database backup and the separate wrapping key when
planning the transfer. Code and schema must match during cutover and rollback;
an older binary cannot run directly against the canonical schema. This chain
provides no automatic transfer or reverse migration.

Repository checks describe source behavior. Updating source, documentation, or
the generated snapshot does not migrate a local or remote application database,
deploy a Worker, or prove a live environment was upgraded.
