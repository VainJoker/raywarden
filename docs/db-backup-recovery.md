# Database Backup, Restore, and Time Travel

Centralize your D1 operational playbooks here: backup automation, restore flows, and point-in-time recovery.

## GitHub Actions Backups

> [!NOTE] To use this backup feature, you must fork this repository and configure the same three required secrets as described in the [CI/CD deployment](deployment.md#cicd-deployment-with-github-actions) section in advance: `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`, and `D1_DATABASE_ID`.

This project includes a GitHub Action workflow that automatically backs up your D1 database to S3-compatible storage daily. The backup runs at 04:00 UTC (1 hour after the cleanup task).

> [!NOTE] **Important Notes:** 
> - **Manual trigger required for first run:** You must manually trigger the Action once (GitHub Actions → Backup D1 Database to S3 → Run workflow) before scheduled backups will run automatically.
> - **Ensure your S3 bucket is set to private access** to prevent data leaks and avoid unnecessary public traffic costs.
> - **⚠️ CRITICAL: Do NOT use R2 from the same Cloudflare account as your Worker** for backups. If your Cloudflare account gets suspended or banned, you will lose access to both your Worker and your backup storage, resulting in complete data loss. Always use a separate Cloudflare account or a different S3-compatible storage provider (AWS S3, Backblaze B2, MinIO, etc.) for backups to ensure redundancy and disaster recovery.

### Required Secrets for Backup

Add the following secrets to your GitHub repository (`Settings > Secrets and variables > Actions`):

| Secret | Required | Description |
|--------|----------|-------------|
| `S3_ACCESS_KEY_ID` | yes | Your S3 access key ID |
| `S3_SECRET_ACCESS_KEY` | yes | Your S3 secret access key |
| `S3_BUCKET` | yes | The S3 bucket name for storing backups |
| `S3_REGION` | yes | The S3 region (e.g., `us-east-1`). If unsure, use `auto` |
| `S3_ENDPOINT` | no | Custom S3 endpoint URL. Defaults to AWS S3 if not set. Required for S3-compatible services (MinIO, Cloudflare R2, Backblaze B2, etc.) |
| `BACKUP_ENCRYPTION_KEY` | no | Optional encryption passphrase. If set, backups will be encrypted with AES-256. **Strongly recommended** since the database contains unencrypted user metadata (emails, item counts) |

### Backup Features

* **Automatic Daily Backups:** Production database is backed up daily at 04:00 UTC
* **Manual Trigger:** You can manually trigger a backup from the GitHub Actions tab
* **Environment Selection:** When triggering manually, you can choose to backup either `production` or `dev` database
* **Compression:** Backups are compressed using gzip to save storage space
* **Optional Encryption:** If `BACKUP_ENCRYPTION_KEY` is set, backups are encrypted with AES-256-CBC (PBKDF2 key derivation, 100k iterations)
* **Automatic Cleanup:** Old backups older than 30 days are automatically deleted
* **S3-Compatible:** Works with AWS S3, Cloudflare R2, MinIO, Backblaze B2, and any S3-compatible storage

### Backup File Location

Backups are stored in your S3 bucket with the following structure:

```
# Unencrypted backups
s3://your-bucket/warden-worker/production/vault1_prod_YYYY-MM-DD_HH-MM-SS.sql.gz

# Encrypted backups (when BACKUP_ENCRYPTION_KEY is set)
s3://your-bucket/warden-worker/production/vault1_prod_YYYY-MM-DD_HH-MM-SS.sql.gz.enc
```

### Decrypting Backups

If you enabled encryption, use the following command to decrypt a backup:

```bash
openssl enc -aes-256-cbc -d -pbkdf2 -iter 100000 \
  -in vault1_prod_YYYY-MM-DD_HH-MM-SS.sql.gz.enc \
  -out backup.sql.gz \
  -pass pass:"YOUR_ENCRYPTION_KEY"

# Then decompress
gunzip backup.sql.gz
```

### Restoring Database to Cloudflare D1

1. **Download the backup from S3:**

    ```bash
    # Using AWS CLI
    aws s3 cp s3://your-bucket/warden-worker/production/vault1_prod_YYYY-MM-DD_HH-MM-SS.sql.gz.enc ./
    
    # Or with custom endpoint (e.g., R2, MinIO)
    aws s3 cp s3://your-bucket/warden-worker/production/vault1_prod_YYYY-MM-DD_HH-MM-SS.sql.gz.enc ./ \
      --endpoint-url https://your-s3-endpoint.com
    ```

2. **Decrypt the backup (if encrypted):**

    ```bash
    openssl enc -aes-256-cbc -d -pbkdf2 -iter 100000 \
      -in vault1_prod_YYYY-MM-DD_HH-MM-SS.sql.gz.enc \
      -out backup.sql.gz \
      -pass pass:"YOUR_ENCRYPTION_KEY"
    ```

3. **Decompress the backup:**

    ```bash
    gunzip backup.sql.gz
    ```

4. **Restore to Cloudflare D1:**

    First, find your database name using wrangler:

    ```bash
    wrangler d1 list
    ```

    This will show a table with your databases. Look for the `name` column (e.g., `warden-db` for production or `warden-dev` for dev).

    Then restore the backup:

    ```bash
    # Replace DATABASE_NAME with your actual database name (e.g., warden-db)
    
    # First, you may want to clear the existing database (optional, use with caution!)
    # wrangler d1 execute DATABASE_NAME --remote --command "DELETE FROM ciphers; DELETE FROM folders; DELETE FROM users;"
    
    # Import the backup
    wrangler d1 execute DATABASE_NAME --remote --file=backup.sql
    ```

    > [!NOTE] The `--remote` flag is required to execute against your production D1 database. Without it, the command will run against the local development database. 

    > ⚠️ **Troubleshooting: `no such table: main.users` error**
    > 
    > If you encounter this error when importing, it's because `wrangler d1 export` may output tables in an order that doesn't respect foreign key dependencies (e.g., `folders` table is created before `users` table, but `folders` has a foreign key referencing `users`).
    > 
    > **Solution:** Add `PRAGMA foreign_keys=OFF;` at the beginning of your backup.sql file to disable foreign key checks during import:
    > 
    > ```bash
    > # Prepend the PRAGMA statement to your backup file
    > echo -e "PRAGMA foreign_keys=OFF;\n$(cat backup.sql)" > backup.sql
    > 
    > # Then import as usual
    > wrangler d1 execute DATABASE_NAME --remote --file=backup.sql
    > ```
    > 
    > Alternatively, you can manually reorder the SQL statements in the backup file to ensure parent tables (`users`) are created before child tables (`folders`, `ciphers`).

## D1 Time Travel (Point-in-Time Recovery)

Cloudflare D1 provides a built-in Time Travel feature that allows you to restore your database to any point within the last 30 days. This is useful for undoing accidental data modifications or deletions without needing a backup.

To use Time Travel:

1. **Check current restore bookmark:**

    ```bash
    # Replace DATABASE_NAME with your actual database name (e.g., warden-db)
    wrangler d1 time-travel info DATABASE_NAME
    ```

2. **Restore to a specific timestamp:**

    ```bash
    # Restore to a specific point in time (ISO 8601 format)
    wrangler d1 time-travel restore DATABASE_NAME --timestamp=2024-01-15T12:00:00Z
    
    # Or restore to a specific bookmark
    wrangler d1 time-travel restore DATABASE_NAME --bookmark=<bookmark_id>
    ```

> [!NOTE] Time Travel retains data for 30 days on the free tier. See [Cloudflare D1 Time Travel documentation](https://developers.cloudflare.com/d1/reference/time-travel/) for more details.
