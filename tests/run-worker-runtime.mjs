import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { serializeConfig } from "miniflare";
import { parseJsonc, PROJECT_ROOT as root } from "../scripts/deploy.mjs";

// Run the compiled Worker inside workerd with temporary SQLite and in-memory
// object storage. The test has neither a listener nor directory access beyond its fixture.
const config = parseJsonc(readFileSync(join(root, "wrangler.jsonc"), "utf8"));
const entry = "tests/worker-runtime.mjs";
const suites = readdirSync(join(root, "tests"))
  .filter(name => name.endsWith("-runtime.mjs") && name !== "worker-runtime.mjs" && name !== "run-worker-runtime.mjs")
  .sort();
const inputs = [
  entry,
  ...["runtime-tools.mjs", "runtime-fixture.mjs", ...suites].map(name => `tests/${name}`),
  "build/index.js", "build/index_bg.wasm",
];
const modules = inputs.map(input => {
  const path = join(root, input);
  if (!existsSync(path)) throw new Error(`Missing ${input}; run just build or just dry-run first`);
  const name = basename(input);
  return name.endsWith(".wasm") ? { name, wasm: readFileSync(path) } : { name, esModule: readFileSync(path, "utf8") };
});
const migrationDir = join(root, "sql/migrations");
const schema = readdirSync(migrationDir).filter(name => name.endsWith(".sql")).sort()
  .map(name => readFileSync(join(migrationDir, name), "utf8")).join("\n");
const triggers = [...schema.matchAll(/CREATE TRIGGER\s+(\w+)/gi)].map(match => match[1]);
const tables = [...schema.matchAll(/CREATE TABLE\s+(\w+)/gi)].map(match => match[1]).reverse();
const reset = [...triggers.map(name => `DROP TRIGGER IF EXISTS ${name};`), ...tables.map(name => `DROP TABLE IF EXISTS ${name};`)].join("\n");
modules.push({ name: "runtime-schema.mjs", esModule: `export const schema=${JSON.stringify(schema)};\nexport const reset=${JSON.stringify(reset)};\n` });

const directory = mkdtempSync(join(tmpdir(), "raywarden-worker-runtime-"));
try {
  const sqlite = join(directory, "sqlite");
  const configPath = join(directory, "config.bin");
  mkdirSync(sqlite);
  writeFileSync(configPath, serializeConfig({ services: [
    { name: "runtime", worker: {
      modules,
      compatibilityDate: config.compatibility_date,
      compatibilityFlags: config.compatibility_flags ?? [],
      bindings: [{ name: "SQL", durableObjectNamespace: { className: "SqlRuntime" } }],
      durableObjectNamespaces: [{ className: "SqlRuntime", uniqueKey: "isolated-runtime-tests", enableSql: true }],
      durableObjectStorage: { localDisk: "sqlite" },
      globalOutbound: { name: "blocked" },
    } },
    { name: "blocked", network: { allow: [] } },
    { name: "sqlite", disk: { path: sqlite, writable: true } },
  ] }));
  await new Promise((done, fail) => {
    // The full suite exercises production-cost PBKDF2 in WASM.
    const child = spawn(join(root, "node_modules/.bin/workerd"), ["test", "--binary", configPath], {
      cwd: root, stdio: "inherit", timeout: 600_000, killSignal: "SIGKILL",
    });
    child.once("error", fail);
    child.once("close", (code, signal) => code === 0 ? done() : fail(new Error(`workerd test failed (${code ?? signal})`)));
  });
} finally {
  rmSync(directory, { recursive: true, force: true });
}
