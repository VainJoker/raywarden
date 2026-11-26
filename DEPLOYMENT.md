# Deployment Guide

This guide explains how to deploy Raywarden to Cloudflare Workers, configure required resources and secrets, enroll your first account, and manage updates and backups.

---

## 1. Prerequisites & Cloudflare Resources

Before deploying, set up the following resources in a single **Cloudflare account**:

1. **Account ID**: Copy your 32-character Cloudflare Account ID from the dashboard.
2. **Workers Subdomain or Custom Domain**:
   - **Using `workers.dev`**: Ensure your account has a `workers.dev` subdomain enabled under **Workers & Pages**.
   - **Using a Custom Domain**: Ensure the domain is active on Cloudflare DNS in the same account.
3. **D1 Database**: Create an empty D1 database (e.g., `warden-db`) and record its **Database Name** and **Database ID** (UUID).
   - Leave the database empty. Deployment applies the D1 migrations to create tables and indexes.
4. **R2 Bucket**: Enable R2 on your account and create a private bucket (e.g., `warden-attachments`).
   - Keep public access disabled. Raywarden accesses the bucket privately through its Worker binding.

> **Note:** You do not need to pre-create the Worker itself in the Cloudflare Dashboard; the deployment process creates and configures it automatically.

---

## 2. Configure `wrangler.jsonc`

Edit the top-level production fields in [wrangler.jsonc](wrangler.jsonc) with your Worker name, D1 database name/ID, and R2 bucket name:

```jsonc
"name": "raywarden",
"workers_dev": true,
"d1_databases": [{
  "binding": "DB",
  "database_name": "warden-db",
  "database_id": "your-d1-database-uuid",
  "migrations_dir": "sql/migrations"
}],
"r2_buckets": [{
  "binding": "ATTACHMENTS_BUCKET",
  "bucket_name": "warden-attachments"
}]
```

### Custom Domain (Optional)

To serve Raywarden on a custom domain instead of `workers.dev`, set `"workers_dev": false` and add a `custom_domain` route at the top level of `wrangler.jsonc`:

```jsonc
"workers_dev": false,
"routes": [{ "pattern": "vault.example.com", "custom_domain": true }]
```

Do not include a scheme (`https://`), path, or wildcard in `pattern`. During deployment, the deploy script automatically detects your custom domain (or resolves your `workers.dev` subdomain) and sets the Worker's `DOMAIN` secret to that origin.

---

## 3. Generate Credentials & Secrets

### 1. Cloudflare API Token

In the Cloudflare Dashboard under **My Profile → API Tokens**, create an API token using the **Edit Cloudflare Workers** template, scoped to your account, with the following permissions:

- **Account → Workers Scripts → Edit** (to create/update the Worker, upload secrets, and manage Durable Objects)
- **Account → D1 → Edit** (to verify the database and apply migrations)
- **Account → Workers R2 Storage → Read** or **Edit** (to verify the R2 bucket)
- **Zone → Workers Routes → Edit** and **Zone → Zone → Read** (required only if using a custom domain)

### 2. `KEY_ENCRYPTION_KEY`

Generate a 32-byte random key encoded as unpadded `base64url` (43 characters):

```bash
node --input-type=module -e 'import { randomBytes } from "node:crypto"; console.log(randomBytes(32).toString("base64url"))'
```

This key encrypts the server's JWT signing keys stored in D1. **Back it up securely in a password manager.** Do not change or regenerate this key on future deployments, or existing sessions and API keys will become unreadable.

### 3. `OWNER_SETUP_TOKEN`

Generate a random setup token (32–512 printable characters):

```bash
openssl rand -hex 32
```

This token is used at `/setup` to authorize registering accounts listed in `ALLOWED_EMAILS`. It is separate from your Bitwarden master password.

---

## 4. Deploy with GitHub Actions

Raywarden includes three GitHub Actions workflows:

- **Integration** ([integration.yml](.github/workflows/integration.yml)): Runs tests, lints, coverage, and builds on pushes to `main` and pull requests.
- **Deploy to Cloudflare** ([cloudflare.yml](.github/workflows/cloudflare.yml)): Triggered when a `v*` tag is pushed. It runs the full `Integration` suite, applies D1 migrations, uploads the Worker and secrets, and verifies `/api/alive`.
- **Release-plz** ([release.yml](.github/workflows/release.yml)): Optional automated release workflow that maintains version-bump PRs on `main` and creates `vX.Y.Z` tags when merged.

### Configure GitHub Environment Secrets

In your GitHub repository, go to **Settings → Environments**, create an environment named `production`, and add these five **Environment secrets**:

| Secret | Value |
| --- | --- |
| `CLOUDFLARE_API_TOKEN` | Your Cloudflare API token |
| `CLOUDFLARE_ACCOUNT_ID` | Your 32-character Cloudflare Account ID |
| `ALLOWED_EMAILS` | Comma- or newline-separated list of allowed email addresses (e.g., `alice@example.com,bob@example.com`) |
| `KEY_ENCRYPTION_KEY` | The 43-character `base64url` key generated in Section 3 |
| `OWNER_SETUP_TOKEN` | The setup token generated in Section 3 |

If you restrict which branches or tags can deploy to the `production` environment, add a **Tag** rule allowing `v*`.

### Trigger a Deployment

#### Option A: Push a Version Tag Manually

Once your `wrangler.jsonc` changes are on `main`, create and push a version tag matching `[package].version` in `Cargo.toml`:

```bash
git switch main
git pull --ff-only
git tag -a v0.1.2 -m "Release v0.1.2"
git push origin v0.1.2
```

Monitor the deployment under **Actions → Deploy to Cloudflare**.

#### Option B: Automated Releases with Release-plz

To use automated release PRs and tagging, add a **Repository secret** (under **Settings → Secrets and variables → Actions → Repository secrets**, not inside the `production` environment):

| Secret | Value |
| --- | --- |
| `RELEASE_PLZ_TOKEN` | A fine-grained GitHub Personal Access Token scoped to this repository with **Contents: Read and write** and **Pull requests: Read and write** |

When changes are pushed to `main`, Release-plz opens or updates a release PR. Merging that PR automatically creates the `vX.Y.Z` tag and triggers **Deploy to Cloudflare**.

---

## 5. Manual CLI Deployment (Alternative)

To deploy directly from a local machine instead of GitHub Actions, export the required environment variables in your terminal and run `just deploy`:

```bash
export CLOUDFLARE_API_TOKEN="your-cloudflare-api-token"
export CLOUDFLARE_ACCOUNT_ID="your-cloudflare-account-id"
export ALLOWED_EMAILS="owner@example.com"
export KEY_ENCRYPTION_KEY="your-43-char-base64url-key"
export OWNER_SETUP_TOKEN="your-setup-token"

just deploy
```

`just deploy` builds the release bundle, verifies your Cloudflare resources, runs pending D1 migrations, uploads the Worker and secrets, and verifies the `/api/alive` health check.

---

## 6. Create Your First Account & Verify

1. Open `https://<your-domain>/setup` in your browser.
2. Enter your `OWNER_SETUP_TOKEN`. Upon verification, the server sets a 10-minute `HttpOnly` enrollment cookie and redirects you to `/#/signup`.
3. Register using an email address from `ALLOWED_EMAILS` and set a strong master password.
4. Sign in to the Web Vault, create a test item, and verify that locking, unlocking, and syncing work as expected.
5. In Bitwarden browser extensions, desktop, or mobile apps, select **Self-hosted** on the login screen and set the server URL to `https://<your-domain>`.

You can also verify the public endpoints from your terminal:

```bash
vault_url='https://vault.example.com'
curl --fail-with-body -sS "$vault_url/api/alive"
curl --fail-with-body -sS "$vault_url/api/config"
```

> **Tip:** Once all intended accounts are registered, you may remove `OWNER_SETUP_TOKEN` from your GitHub Secrets and delete the `OWNER_SETUP_TOKEN` secret in the Cloudflare Worker settings to disable `/setup` until you want to enroll another account.

---

## 7. Updates, Optional Secrets & Backups

### Updating Raywarden

Push new changes to `main` and publish a new `vX.Y.Z` tag (either manually or by merging the Release-plz PR). During updates, omitted `ALLOWED_EMAILS`, `KEY_ENCRYPTION_KEY`, or `OWNER_SETUP_TOKEN` values are preserved on the existing Worker, while `DOMAIN` is refreshed automatically.

### Optional Secrets (Email, Push & Admin Notifications)

The GitHub Actions workflow uploads `ALLOWED_EMAILS`, `KEY_ENCRYPTION_KEY`, `OWNER_SETUP_TOKEN`, and `DOMAIN`. If you enable optional integrations such as an email webhook (`MAIL_WEBHOOK_URL`, `MAIL_WEBHOOK_TOKEN`), admin notifications (`WEWORK_WEBHOOK_URL`, `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`), Turnstile (`TURNSTILE_SITE_KEY`, `TURNSTILE_SECRET_KEY`), or HIBP (`HIBP_API_KEY`), configure those secrets directly in the Cloudflare Dashboard under **Worker → Settings → Variables and Secrets** (or via `wrangler secret put`). Because `keep_vars` and existing secrets are preserved across deployments, subsequent releases will retain them.

Email delivery requires a sending service. `ALLOWED_EMAILS` controls enrollment and cannot provide a sender identity. A `workers.dev` address does not supply a sending domain: [Cloudflare native email requires a domain configured for Email Service](https://developers.cloudflare.com/email-service/configuration/send-bindings/). No native email binding or additional sender variable is enabled in this project.

### Backups & Recovery

To restore a Raywarden instance completely, back up and retain these three items together:
1. **D1 Database Export**: Contains accounts, encrypted ciphers, device sessions, `jwt_keys`, and `d1_migrations`.
2. **R2 Bucket Objects**: Contains the encrypted binary files for attachments and File Sends.
3. **`KEY_ENCRYPTION_KEY`**: Required to decrypt `jwt_keys` in D1.

---

## 8. Troubleshooting

| Issue | Solution |
| --- | --- |
| **Pushing to `main` did not deploy** | Deployments run on `v*` tags. Push a new `vX.Y.Z` tag or merge the Release-plz PR. |
| **`First deployment requires supplied Secrets`** | Ensure `ALLOWED_EMAILS` and `KEY_ENCRYPTION_KEY` are set in the GitHub `production` environment secrets. |
| **`Invalid KEY_ENCRYPTION_KEY`** | Must be a 43-character unpadded `base64url` string (32 random bytes). Use the Node command in [Section 3](#2-key_encryption_key). |
| **`PBKDF2 key derivation failed: await bit derivation` during registration or login** | Update to a release using RustCrypto for all server password verifiers, avoiding Workers' Web Crypto iteration limit. Existing verifier hashes and iteration counts remain compatible; no database reset or client KDF change is needed. |
| **`Email delivery is not configured`** | Configure a working `MAIL_WEBHOOK_URL` to enable account email delivery. `ALLOWED_EMAILS` authorizes registration; it does not provide an email sending service. |
| **D1 ID or name mismatch** | Verify that `database_id` and `database_name` in `wrangler.jsonc` match the D1 database in your target Cloudflare account. |
| **`workers.dev` subdomain lookup fails** | Enable a `workers.dev` subdomain in **Workers & Pages**, or configure a `custom_domain` route in `wrangler.jsonc`. |
| **Migration fails due to existing tables** | Start with an empty D1 database and let Wrangler apply the migrations. |
| **`/setup` returns `401` or `409`** | Check that `OWNER_SETUP_TOKEN` matches, at least one email in `ALLOWED_EMAILS` is not yet registered, and you are accessing the canonical HTTPS origin. |
| **`Release-plz` fails due to missing token** | Add `RELEASE_PLZ_TOKEN` as a **Repository secret** (not an Environment secret) with Contents and Pull requests read/write access. |
