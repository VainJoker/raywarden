import { execFile } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { promisify } from "node:util";

const run = promisify(execFile);
export const WEB_VAULT_VERSION = JSON.parse(await readFile(new URL("../../package.json", import.meta.url), "utf8")).config.webVaultVersion;

export async function writeVault(directory, version = WEB_VAULT_VERSION, html = "<html><head></head><body><app-root></app-root></body></html>") {
  await mkdir(directory, { recursive: true });
  await writeFile(join(directory, "vw-version.json"), JSON.stringify({ version }));
  await writeFile(join(directory, "index.html"), html);
}

export async function archiveVault(source, destination) {
  await run("tar", ["-czf", destination, "-C", dirname(source), basename(source)]);
  return destination;
}
