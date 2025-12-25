# Deployment

This page covers the two deployment paths. Pick the one that fits your workflow and infrastructure.

## CLI Deployment

1. **Clone the repository:**

   ```bash
   git clone https://github.com/your-username/warden-worker.git
   cd warden-worker
   ```

2. **Create a D1 Database:**

   ```bash
   wrangler d1 create warden-db
   ```

3. **(Optional) Enable R2 Bucket for Attachments:**

   If you want to use file attachments:

   ```bash
   # Create the production bucket
   wrangler r2 bucket create warden-attachments
   ```

   Then enable the R2 binding in `wrangler.toml` by uncommenting the R2 bucket configuration sections.

   **Note:** Attachments are optional. If you don't enable R2 bindings, attachment functionality will be disabled but all other features will work normally.

4. **Configure your Database ID:**

   When you create a D1 database, Wrangler will output the `database_id`. To avoid committing this secret to your repository, this project uses an environment variable to configure the database ID.

   You have two options:

   **Option 1: (Recommended) Use a `.env` file:**

   Create a file named `.env` in the root of the project and add the following line, replacing the placeholder with your actual `database_id`:

   ```
   D1_DATABASE_ID="your-database-id-goes-here"
   ```

   Make sure to add the `.env` file to your `.gitignore` file to prevent it from being committed to git.

   **Option 2: Set an environment variable in your shell:**

   You can set the environment variable in your shell before deploying:

   ```bash
   export D1_DATABASE_ID="your-database-id-goes-here"
   wrangler deploy
   ```

5. **Download the frontend (Web Vault):**

   ```bash
   # Get latest version tag
   LATEST_TAG=$(curl -s https://api.github.com/repos/dani-garcia/bw_web_builds/releases/latest | jq -r .tag_name)

   # Download and extract
   wget "https://github.com/dani-garcia/bw_web_builds/releases/download/$LATEST_TAG/bw_web_${LATEST_TAG}.tar.gz"
   mkdir -p public
   tar -xzf bw_web_${LATEST_TAG}.tar.gz -C public/

   # Move files from web-vault subfolder
   shopt -s dotglob
   mv public/web-vault/* public/
   shopt -u dotglob
   rmdir public/web-vault
   rm bw_web_${LATEST_TAG}.tar.gz
   ```

6. **Set up database and deploy the worker:**

   ```bash
   # Only run once before first deployment
   wrangler d1 execute vault1 --file sql/schema.sql --remote
   # For migrations
   wrangler d1 migrations apply vault1 --remote

   wrangler deploy
   ```

   This will deploy the worker and set up the necessary database tables.

7. **Set environment variables** as `Secret`

- `ALLOWED_EMAILS` your-email@example.com (supports glob patterns like `*@example.com`)
- `JWT_SECRET` a long random string
- `JWT_REFRESH_SECRET` a long random string

8. **Configure your Bitwarden client:**

   In your Bitwarden client, go to the self-hosted login screen and enter the URL of your deployed worker.

   By default, the `*.workers.dev` domain is disabled, since it may throw 1101 error. It's highly recommended to use a custom domain instead; see [Configure Custom Domain](../README.md#configure-custom-domain-optional) for more details.

## CI/CD Deployment with GitHub Actions

This project includes GitHub Actions workflows for automated deployment. This is the recommended approach for production environments as it ensures consistent builds and deployments.

### Required Secrets

Add the following secrets to your GitHub repository (`Settings > Secrets and variables > Actions`):

| Secret | Required | Description |
|--------|----------|-------------|
| `CLOUDFLARE_API_TOKEN` | yes | Your Cloudflare API token |
| `CLOUDFLARE_ACCOUNT_ID` | yes | Your Cloudflare account ID |
| `D1_DATABASE_ID` | yes | Your production D1 database ID |

> [!NOTE] The `CLOUDFLARE_API_TOKEN` must have **both** Worker and D1 permissions:
> - **Edit Cloudflare Workers** - Required for deploying the Worker
> - **Edit D1** - Required for database migrations and backups
> 
> When creating the API token in Cloudflare Dashboard, make sure to add both permissions under "Account" → "Cloudflare Workers" and "Account" → "D1".

### How to Get Your Cloudflare Account ID

1. Log in to the [Cloudflare Dashboard](https://dash.cloudflare.com/)
2. Select your account
3. Your Account ID is displayed in the right sidebar of the Overview page, or in the URL: `https://dash.cloudflare.com/<account-id>`

### Usage

1. **Fork or clone the repository** to your GitHub account

2. **Configure the required secrets** in your repository settings

3. **(Optional) Enable R2 bucket for attachments:**

   If you want to use file attachments:

   1. **Create R2 buckets in Cloudflare Dashboard before running the action:**
      - Go to **Storage & databases** → **R2** → **Create bucket**
      - Create a production bucket (e.g., `warden-attachments`)

   2. **Add the bucket names as GitHub Action secrets:**
      - `R2_NAME` → production bucket name

   The workflows will auto-append the `ATTACHMENTS_BUCKET` binding into `wrangler.toml` when these secrets are present - no manual binding in the Cloudflare console is required.

4. **Manually trigger the `Build` Action** from the GitHub Actions tab in your repository

5. **Monitor the deployment** in the Actions tab of your repository

6. **Set up tables in database manually** in the Cloudflare dashboard

7. **Set environment variables** as `secret` in the Cloudflare dashboard (following the command line deployment steps):
   - `ALLOWED_EMAILS` your-email@example.com (supports glob patterns like `*@example.com`)
   - `JWT_SECRET` a long random string
   - `JWT_REFRESH_SECRET` a long random string

By default, the `*.workers.dev` domain is disabled, since it may throw 1101 error. It's highly recommended to use a custom domain instead; see [Configure Custom Domain](../README.md#configure-custom-domain-optional) for more details.
