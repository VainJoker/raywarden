import { spawn } from "node:child_process";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseJsonc } from "../scripts/deploy.mjs";

// Run the built Worker inside workerd, without opening a listener or using any
// local/remote application database. SQLite lives in a temporary directory;
// object-storage bindings live in memory. The directory is removed on exit.
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const config = parseJsonc(readFileSync(resolve(root, "wrangler.jsonc"), "utf8"));
const entry = "worker-runtime.mjs";
const support = ["runtime-tools.mjs", "runtime-fixture.mjs"];
const runner = basename(fileURLToPath(import.meta.url));
const suites = readdirSync(join(root, "tests"))
  .filter(name => name.endsWith("-runtime.mjs") && name !== entry && name !== runner)
  .sort();
const inputs = [
  ...[entry, ...support, ...suites].map(name => `tests/${name}`),
  "build/index.js", "build/index_bg.wasm",
];
const schemaModule = "runtime-schema.mjs";
for (const input of inputs) {
  if (!existsSync(resolve(root, input))) throw new Error(`Missing ${input}; run just build or just dry-run first`);
}
const directory = mkdtempSync(join(tmpdir(), "raywarden-worker-runtime-"));
try {
  for (const input of inputs) copyFileSync(resolve(root, input), join(directory, basename(input)));
  const migrationFiles = readdirSync(join(root, "sql/migrations")).filter(name => name.endsWith(".sql")).sort();
  const schema = migrationFiles.map(name => readFileSync(join(root, "sql/migrations", name), "utf8")).join("\n");
  const triggers = [...schema.matchAll(/CREATE TRIGGER\s+(\w+)/gi)].map(m => m[1]);
  const tables = [...schema.matchAll(/CREATE TABLE\s+(\w+)/gi)].map(match => match[1]).reverse();
  const reset = [...triggers.map(name => `DROP TRIGGER IF EXISTS ${name};`), ...tables.map(name => `DROP TABLE IF EXISTS ${name};`)].join("\n");
  writeFileSync(join(directory, schemaModule), `export const schema=${JSON.stringify(schema)};\nexport const reset=${JSON.stringify(reset)};\n`);
  mkdirSync(join(directory, "sqlite"));
  const modules = [...inputs.map(input => basename(input)), schemaModule].map(name => {
    const literal = JSON.stringify(name);
    const type = name.endsWith(".wasm") ? "wasm" : "esModule";
    return `      (name = ${literal}, ${type} = embed ${literal})`;
  });
  writeFileSync(join(directory, "config.capnp"), `using Workerd = import "/workerd/workerd.capnp";
const config :Workerd.Config = (
  services = [(name = "runtime", worker = (
    modules = [
${modules.join(",\n")}
    ],
    compatibilityDate = ${JSON.stringify(config.compatibility_date)},
    compatibilityFlags = ${JSON.stringify(config.compatibility_flags ?? [])},
    bindings = [(name = "SQL", durableObjectNamespace = (className = "SqlRuntime"))],
    durableObjectNamespaces = [(className = "SqlRuntime", uniqueKey = "isolated-runtime-tests", enableSql = true)],
    durableObjectStorage = (localDisk = "sqlite"),
    globalOutbound = "blocked"
  )), (name = "blocked", network = (allow = [])), (name = "sqlite", disk = (path = ${JSON.stringify(join(directory, "sqlite"))}, writable = true))],
);
`);
  await new Promise((done, fail) => {
    const child = spawn(resolve(root, "node_modules/.bin/workerd"), ["test", join(directory, "config.capnp")], { cwd: root, stdio: "inherit", timeout: 120_000, killSignal: "SIGKILL" });
    child.once("error", fail);
    child.once("close", (code, signal) => code === 0 ? done() : fail(new Error(`workerd test failed (${code ?? signal})`)));
  });
} finally {
  rmSync(directory, { recursive: true, force: true });
}
