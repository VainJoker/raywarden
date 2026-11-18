import { readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export function pinnedVersion(root) {
  const version = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).config?.webVaultVersion;
  if (typeof version !== "string" || !/^\d{4}\.\d+\.\d+$/.test(version)) {
    throw new Error("package.json config.webVaultVersion must pin a release such as 2026.7.0");
  }
  return version;
}

export function patchUi(root, directory) {
  const version = pinnedVersion(root);
  const metadata = JSON.parse(readFileSync(join(directory, "vw-version.json"), "utf8"));
  if (metadata?.version !== version) throw new Error(`Web Vault version ${metadata?.version} does not match pinned ${version}`);
  const index = join(directory, "index.html");
  let html = readFileSync(index, "utf8");
  if (!/<\/head\s*>/i.test(html)) throw new Error("Web Vault index.html has no closing head tag");
  html = html.replace(/<script\b[^>]*>\s*\/\* turnstile-send-guard[\s\S]*?<\/script\s*>/gi, "");
  html = html.replace(/<script\b[^>]*\bsrc\s*=\s*(["'])\/?js\/raywarden\.js\1[^>]*>\s*<\/script\s*>/gi, "");
  if (!/<link\b[^>]*\bhref\s*=\s*(["'])\/?css\/vaultwarden\.css\1/i.test(html)) {
    html = html.replace(/<\/head\s*>/i, '<link rel="stylesheet" href="css/vaultwarden.css"></head>');
  }
  html = html.replace(/<\/head\s*>/i, '<script defer src="js/raywarden.js"></script></head>');
  writeFileSync(index, html);
  return version;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const [first, second, ...extra] = process.argv.slice(2);
    if (!first || !second || extra.length) throw new Error("Usage: node scripts/patch-ui.mjs ROOT DIRECTORY | --version ROOT");
    if (first === "--version") console.log(pinnedVersion(second));
    else patchUi(first, second);
  } catch (error) {
    console.error(`UI preparation failed: ${error.message}`);
    process.exitCode = 1;
  }
}
