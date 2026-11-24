# Raywarden

Raywarden is a Bitwarden-compatible server for Cloudflare Workers. It uses Rust/WASM, Axum, D1, R2 with optional KV storage, and a pinned prebuilt Web Vault. Clients encrypt vault contents. The server stores ciphertext, authentication material, and file metadata.

The project supports personal vaults for multiple independent accounts and multiple devices per account. Registration requires an exact email address in `ALLOWED_EMAILS` and private authorization through `/setup`. Adding an address grants eligibility and leaves account creation to the client. Existing accounts can still sign in after allowlist changes.

Supported features include V1/V2 account encryption, vault items and folders, attachments, Text and File Send, and authentication with TOTP, email, or Passkey where configured. Attachments and File Send use separate metadata and data uploads. Clients using the older one-step uploads or the legacy three-route TOTP setup flow need to use the current protocols. Organizations, enterprise sharing, SSO, and emergency access are outside the personal-vault scope. See the [architecture and client compatibility notes](docs/architecture.md#客户端兼容范围).

## Local development

Install Node as pinned in `.node-version`, npm, rustup, and the just version in `package.json`. SQL tests use Python 3. Bash, curl, and tar are used for tool and frontend preparation.

```bash
just dev
```

This prepares missing tools, updates the pinned frontend, applies migrations to local D1, and starts the Worker at `https://localhost:8787`. To create accounts locally, set `OWNER_SETUP_TOKEN` in the ignored `.dev.vars` file and visit `/setup`. Local D1 and R2 use separate development resources.

| Command | Purpose |
| --- | --- |
| `just setup` | Prepare the pinned tools and locked dependencies |
| `just ci` | Run format, Rust, JavaScript, SQL, and WASM checks |
| `just build` | Build the Worker with the pinned worker-build |
| `just test-worker` | Run the built WASM with workerd and temporary SQLite |
| `just ui-offline` | Refresh overrides in an existing pinned Web Vault |
| `just ui-download` / `just ui-archive PATH` | Install the pinned release from a download or a local archive |
| `just db-migrate` | Apply pending migrations to local D1 |

The files in [sql/migrations](sql/migrations/README.md) define the database structure. Existing instances with an older migration history need a separately planned data transfer. `sql/schema.sql` is a generated reference for reviewing the schema. Keep an independent backup of the application data and wrapping secret before a migration or rollback.

## Deployment and maintenance

Follow the [deployment guide](docs/deployment.md) for Cloudflare resources, GitHub Secrets, and first account creation. The Cloudflare workflow starts on `v*` tag pushes, reuses Integration to verify and build the Worker, then deploys the verified artifact from the same run. For a local production preflight, use `just dry-run`. Use `just db-migrate production` for a standalone production migration.

Production requires `ALLOWED_EMAILS`, `KEY_ENCRYPTION_KEY`, and `DOMAIN`. The deploy script derives `DOMAIN` from the configured public endpoint. Configure `OWNER_SETUP_TOKEN` to authorize registration and store the wrapping key separately from the D1 backup.

- [Architecture and source layout](docs/architecture.md)
- [Runtime configuration and limits](docs/runtime-config.md)
- [Backup and recovery](docs/db-backup-recovery.md)
- [Naming and migration compatibility](docs/naming-conventions.md)

## License

[MIT](LICENSE).
