import { randomUUID } from "node:crypto";
import { readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { parseJsonc, PROJECT_ROOT } from "./deploy.mjs";

const config = parseJsonc(readFileSync(resolve(PROJECT_ROOT, "wrangler.jsonc"), "utf8"));
// Wrangler filters local dotenv bindings whenever a secrets object is present.
delete config.secrets;

// Keep relative bindings and dotenv discovery rooted at the project directory.
const output = resolve(PROJECT_ROOT, ".wrangler-local.generated.json");
const staged = `${output}.${randomUUID()}.tmp`;
try {
  writeFileSync(staged, `${JSON.stringify(config, null, 2)}\n`, { flag: "wx", mode: 0o600 });
  renameSync(staged, output);
} finally {
  rmSync(staged, { force: true });
}
