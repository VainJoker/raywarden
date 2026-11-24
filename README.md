# Raywarden

Raywarden is a lightweight, Bitwarden-compatible password manager server built for **Cloudflare Workers**. Written in Rust and compiled to WebAssembly, it pairs a pinned Bitwarden Web Vault with Cloudflare D1, R2 (or KV), and Durable Objects.

All vault data is encrypted and decrypted locally by official Bitwarden clients. The server stores only ciphertext, authentication verifiers, and file metadata.

## Features

- **Personal Vaults**: Full support for logins, secure notes, cards, identities, SSH keys, folders, favorites, archiving, trash auto-cleanup, and vault imports/exports.
- **Multiple Accounts & Devices**: Supports multiple independent personal accounts and multiple logged-in devices per account with strict data isolation.
- **Private Enrollment**: Public sign-ups are disabled. Creating an account requires both an exact email match in `ALLOWED_EMAILS` and owner authorization via `/setup`.
- **Modern Cryptography**: Supports PBKDF2-SHA256 and Argon2id client KDFs, account encryption, key rotation, and per-account server password verifiers.
- **Attachments & Bitwarden Send**: Streaming file uploads and downloads for vault attachments and Text/File Sends, backed by R2 multipart storage and automatic orphan cleanup.
- **Multi-Factor & Passwordless Auth**: Supports TOTP authenticator apps, email verification codes, WebAuthn/FIDO2 security keys, 2FA recovery codes, Passkey login (with PRF support), and login approval requests from trusted devices.
- **Real-Time Sync**: Push notifications over WebSockets keep connected clients in sync.

> **Scope:** Raywarden is designed for personal and family use. Enterprise features such as organizations, shared collections, SSO, and emergency access are intentionally omitted.

## Architecture

- **Worker & Axum Router (`src/api/`)**: Serves the API, enforces security headers and CORS, and routes static assets to the prebuilt Web Vault.
- **Durable Objects (`src/api/edge/`)**:
  - `notifydo`: Manages SignalR WebSocket connections and broadcasts real-time sync events.
  - `heavydo`: Offloads CPU-intensive authentication requests and streaming file uploads.
- **Database (`src/models/`, `sql/migrations/`)**: Uses Cloudflare D1 (SQLite) with atomic batch transactions and optimistic concurrency guards.
- **Object Storage (`src/infra/storage.rs`)**: Stores encrypted attachments and File Sends in Cloudflare R2 (with optional Workers KV fallback).

## Quick Start (Local Development)

### Prerequisites

- **Node.js** (v24+, see `.node-version`) and **npm**
- **Rust** via `rustup` (automatically selects the toolchain and `wasm32-unknown-unknown` target from `rust-toolchain.toml`)
- **just** command runner
- **Python 3** (for SQL schema and query tests)
- Standard shell tools: `bash`, `curl`, `tar`

### Run Locally

```bash
just dev
```

This command installs required build tools, downloads and patches the Web Vault into `static/web-vault`, applies D1 migrations locally, and starts the development server at `https://localhost:8787`.

To register a local account (`owner@example.test` is allowed by default in `wrangler.jsonc`):

1. Create a `.dev.vars` file in the project root with a setup token (32–512 characters):
   ```dotenv
   OWNER_SETUP_TOKEN="replace-with-output-of-openssl-rand-hex-32"
   ```
2. Restart `just dev`, visit `https://localhost:8787/setup`, enter your token, and create your account in the Web Vault.

### Development Commands

| Command | Description |
| --- | --- |
| `just dev` | Start the local HTTPS server (`https://localhost:8787`) |
| `just setup` | Install pinned toolchains, `worker-build`, and dependencies |
| `just ci` | Run formatting checks, unit/SQL/JS tests, and Clippy lints |
| `just build` | Build the release Worker bundle |
| `just test-worker` | Run end-to-end tests against the compiled WASM Worker in `workerd` |
| `just test-d1` | Test D1 migrations and R2 file lifecycles in a local Wrangler instance |
| `just ui` | Download or refresh the pinned Web Vault assets |
| `just db-migrate` | Apply pending migrations to the local D1 database |
| `just clean` | Remove build artifacts and temporary caches |

## Configuration

Runtime configuration is defined in [wrangler.jsonc](wrangler.jsonc). Sensitive values are configured as Worker Secrets (or in `.dev.vars` for local development).

### Required Secrets

| Secret | Description |
| --- | --- |
| `ALLOWED_EMAILS` | Comma- or newline-separated list of email addresses allowed to register |
| `KEY_ENCRYPTION_KEY` | 32-byte key (43-character unpadded `base64url`) used to encrypt server signing keys in D1 |
| `OWNER_SETUP_TOKEN` | Secret token (32–512 characters) used at `/setup` to authorize account registration |
| `DOMAIN` | Public HTTPS origin of the service (set automatically by the deploy script) |

### Common Optional Variables

| Variable | Default | Description |
| --- | --- | --- |
| `JWT_DURATION_SECONDS` | `3600` | Access token lifetime in seconds |
| `TWO_FACTOR_REMEMBER_DAYS` | `30` | "Remember this device" duration in days (`1`–`90`) |
| `TRASH_AUTO_DELETE_DAYS` | `30` | Days before soft-deleted items are permanently purged (`<= 0` disables) |
| `ATTACHMENT_MAX_BYTES` | Unlimited | Maximum size in bytes for a single attachment |
| `ATTACHMENT_TOTAL_LIMIT_KB` | Unlimited | Per-user attachment storage quota in KiB |
| `SEND_MAX_BYTES` | `99614720` (95 MiB) | Maximum size in bytes for a File Send (KV fallback max is 25 MiB) |
| `USER_SEND_LIMIT_KB` | Unlimited | Per-user File Send storage quota in KiB |
| `CORS_ALLOWED_ORIGINS` | `*` | Comma-separated list of allowed CORS origins |
| `WEBAUTHN_ALLOWED_ORIGINS` | `DOMAIN` | Additional allowed origins for browser extension or mobile WebAuthn |
| `MAIL_WEBHOOK_URL` / `MAIL_WEBHOOK_TOKEN` | Unset | Webhook endpoint and bearer token for sending verification emails |
| `NOTIFY_EVENTS` / `NOTIFY_LEVEL` | `none` / `info` | Admin event notifications via Telegram or WeCom webhooks |
| `TURNSTILE_SITE_KEY` / `TURNSTILE_SECRET_KEY` | Unset | Cloudflare Turnstile keys for public Send access protection |
| `HIBP_API_KEY` | Unset | Have I Been Pwned API key for password breach checks |
| `DISABLE_ICON_DOWNLOAD` | `false` | Disable fetching website icons |

## Deployment

See **[DEPLOYMENT.md](DEPLOYMENT.md)** for instructions on provisioning Cloudflare resources, configuring GitHub Actions or CLI deployments, creating your first account, and backing up your data.

## License

[MIT](LICENSE)
