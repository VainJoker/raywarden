# D1 migrations

This directory is the authoritative runtime source for database structure.
The baseline groups the original DDL into five functional files. Subsequent
migrations add runtime-managed keys, equivalent-domain refresh state, V2
account envelopes and durable file cleanup. Remaining feature gaps are tracked
in the feature-parity document.

| File | Contents |
| --- | --- |
| `0001_accounts.sql` | Users |
| `0002_vault.sql` | Folders, ciphers, attachments, pending attachments, global equivalent domains |
| `0003_authentication.sql` | Devices, auth requests, two-factor, WebAuthn, API keys |
| `0004_verification.sql` | Verification codes and Turnstile redemptions |
| `0005_sends.sql` | Sends |
| `0006_jwt_keys.sql` | Persistent server signing keys |
| `0007_global_domains_cache.sql` | Global equivalent-domain refresh state |
| `0008_account_encryption.sql` | V2 account envelopes and PRF/approval generation snapshots |
| `0009_file_lifecycle.sql` | File object pointers and deletion outbox triggers |
| `0010_single_user.sql` | Unique owner constraint, including competing initial registrations |

New databases apply these files in order with Wrangler's native
`d1 migrations apply`. Each table is declared in full, followed by its indexes;
the old add-column patch chain is no longer used. `CREATE TABLE` has no
`IF NOT EXISTS`: Wrangler skips recorded migrations rather than suppressing
duplicate-object errors.

`sql/schema.sql` is a generated snapshot of the current application structure,
not a second migration or initialization path. It is useful for reading all
tables at once, reviewing the net effect of migrations, or creating a disposable
SQLite database for analysis. It contains no business or seed data and no
`d1_migrations` history, so it is not a backup or a production restore file.

After adding a migration, run `just schema` to regenerate the snapshot and
`just test-sql` to check that replaying it matches the complete migration chain.
The existing `just ci` command also runs this consistency check.
Do not hand-edit the snapshot, import it into an application database, or follow
it with the full historical migrations. Normal `just dev`, deployment and
regression test setup continue to use migrations, not the snapshot.

Wrangler creates and updates `d1_migrations` as files actually execute. The
current complete chain has ten records; do not prefill migration history.

## Commands

From the repository root:

```bash
just dev                  # Apply pending local migrations, then start locally.
just db-migrate           # Apply local migrations only (default: local).
just db-migrate local     # Same explicit local target.
just schema               # Regenerate the structure snapshot in memory only.
```

Local commands use `wrangler.local.jsonc`, `--local` and `.wrangler/local`.
Remote migration requires an explicit `just db-migrate production`; it
validates production configuration before using `--remote`. Do not use a remote command to validate a local change.

## Baseline boundary

This is a new baseline, not an in-place upgrade path for databases with the old
`d1_migrations` records. Do not apply the current migration chain directly to an old
application database or invent replacement history. Transferring existing data
to this baseline needs a separate plan; no compatibility mapping is provided.

This change did not clear or modify the user's existing local database, read
or write a remote database, or run a migration against an application database. Native migration errors
stop execution; they are not ignored to make the new baseline fit an old one.

## Future changes

- Add changes as `0011_*.sql` and later, using Wrangler's migration creation
  command and reviewing its generated name.
- After this baseline is established, preserve applied files and append changes
  instead of editing or reordering them.
- Test new databases by applying the complete current chain from `0001`, and
  test later upgrades against databases created from this baseline.
- Apply pending migrations successfully before uploading Worker code that
  depends on them. Use the configured local or explicit remote environment.

The baseline creates empty tables. Later migrations may alter tables and
transform existing data; `0008` binds existing PRF material to its current
account generation without upgrading account encryption or clearing key IDs.
Runtime initialization stores JWT keys in
`jwt_keys` once; preserve that row with the database, including during recovery.
Global equivalent domains are fetched and cached automatically, independently
of user-defined groups. Their cache can be rebuilt; signing keys cannot.

`0010` enforces the single-user design with a unique index over a constant.
It preserves an existing sole owner and rejects every second account, even
when two first registrations race. If multiple users already exist, migration
fails without removing or merging them; review the database and its backup
before deciding how to transfer it to a single-owner installation.
