import { execFile } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { promisify } from "node:util";

const run = promisify(execFile);
export const WEB_VAULT_VERSION = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8")).config.webVaultVersion;

export async function writeVault(directory, version = WEB_VAULT_VERSION, html = "<html><head></head><body><app-root></app-root></body></html>") {
  await mkdir(directory, { recursive: true });
  await writeFile(join(directory, "vw-version.json"), JSON.stringify({ version }));
  await writeFile(join(directory, "index.html"), html);
}

export async function archiveVault(source, destination) {
  await run("tar", ["-czf", destination, "-C", dirname(source), basename(source)]);
  return destination;
}

export const databaseId = "11111111-1111-4111-8111-111111111111";

export function productionConfig({ name, databaseName, bucketName }) {
  return {
    name,
    secrets: { required: ["DOMAIN", "KEY_ENCRYPTION_KEY"] },
    observability: { redact_query_string: true, logs: { enabled: true, invocation_logs: false } },
    routes: [{ pattern: "vault.example.test", custom_domain: true }],
    d1_databases: [{
      binding: "DB", database_name: databaseName, database_id: databaseId, migrations_dir: "sql/migrations",
    }],
    r2_buckets: [{ binding: "ATTACHMENTS_BUCKET", bucket_name: bucketName }],
    ratelimits: [
      { name: "LOGIN_RATE_LIMITER", namespace_id: "3101", simple: { limit: 5, period: 60 } },
      { name: "SEND_ACCESS_RATE_LIMITER", namespace_id: "3103", simple: { limit: 15, period: 60 } },
    ],
  };
}
