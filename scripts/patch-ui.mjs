import { readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export function readPinnedVaultVersion(root) {
  const version = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).config?.webVaultVersion;
  if (typeof version !== "string" || !/^\d{4}\.\d+\.\d+$/.test(version)) {
    throw new Error("package.json config.webVaultVersion must pin a release such as 2026.7.0");
  }
  return version;
}

const CLOSE_HEAD = /<\/head\s*>/i;

export function readVaultIndex(root, directory) {
  const version = readPinnedVaultVersion(root);
  const metadata = JSON.parse(readFileSync(join(directory, "vw-version.json"), "utf8"));
  if (metadata?.version !== version) throw new Error(`Web Vault version ${metadata?.version} does not match pinned ${version}`);
  const index = join(directory, "index.html");
  const html = readFileSync(index, "utf8");
  if (!CLOSE_HEAD.test(html)) throw new Error("Web Vault index.html has no closing head tag");
  return { version, index, html };
}

// One compiled policy also drives the API middleware. `_headers` only affects
// assets; Worker and DO responses apply the same defaults in Rust.
export function renderAssetHeaders(root) {
  const policy = JSON.parse(readFileSync(join(root, "static/security-headers.json"), "utf8"));
  const lines = ["# Generated from static/security-headers.json by patch-ui.mjs.", "/*"];
  const attach = (entries) => {
    for (const [name, value] of Object.entries(entries)) {
      if (!/^[A-Za-z][A-Za-z-]*$/.test(name) || typeof value !== "string" || /[\r\n]/.test(value)) {
        throw new Error("Invalid compiled security header");
      }
      const line = `  ${name}: ${value}`;
      if (line.length > 2000) throw new Error("Security header exceeds Cloudflare's line limit");
      lines.push(line);
    }
  };
  // HTML may be served through clean URLs or a 404/SPA fallback. Default to
  // no-store, then opt known static resource suffixes into revalidation.
  attach({ ...policy.common, ...policy.document, "Cache-Control": policy.dynamicCache });
  // Matching _headers rules append rather than replace. Detach before setting
  // a narrower policy, otherwise CSP/cache directives can conflict.
  const imageExtensions = new Set(["svg", "png", "jpg", "jpeg", "gif", "webp", "ico", "avif"]);
  for (const extension of ["js", "mjs", "css", "wasm", "woff", "woff2", "ttf", "otf", "eot", "svg", "png", "jpg", "jpeg", "gif", "webp", "ico", "avif", "json", "webmanifest", "txt", "xml"]) {
    lines.push("", `/*.${extension}`, "  ! Cache-Control");
    attach({ "Cache-Control": policy.assetCache });
    if (imageExtensions.has(extension)) {
      lines.push("  ! Content-Security-Policy");
      attach({ "Content-Security-Policy": policy.image["Content-Security-Policy"] });
    }
  }
  // Authenticator connector pages must work in client-owned popups/frames.
  for (const path of ["/*connector.html", "/*connector", "/*connector/"]) {
    lines.push("", path, "  ! Content-Security-Policy", "  ! X-Frame-Options", "  ! Cache-Control");
    attach({ "Cache-Control": policy.dynamicCache });
  }
  lines.push("");
  return lines.join("\n");
}

export function patchUi(root, directory) {
  const { version, index, html } = readVaultIndex(root, directory);
  const headers = renderAssetHeaders(root);
  const cleaned = html
    .replace(/<script\b[^>]*>\s*\/\* turnstile-send-guard[\s\S]*?<\/script\s*>/gi, "")
    .replace(/<script\b[^>]*\bsrc\s*=\s*(["'])\/?js\/raywarden\.js\1[^>]*>\s*<\/script\s*>/gi, "");
  const stylesheet = /<link\b[^>]*\bhref\s*=\s*(["'])\/?css\/vaultwarden\.css\1/i.test(cleaned)
    ? "" : '<link rel="stylesheet" href="css/vaultwarden.css">';
  const patched = cleaned.replace(CLOSE_HEAD, `${stylesheet}<script defer src="js/raywarden.js"></script></head>`);
  writeFileSync(index, patched);
  writeFileSync(join(directory, "_headers"), headers);
  return version;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const [first, second, ...extra] = process.argv.slice(2);
    if (!first || !second || extra.length) throw new Error("Usage: node scripts/patch-ui.mjs ROOT DIRECTORY | --version ROOT");
    if (first === "--version") console.log(readPinnedVaultVersion(second));
    else patchUi(first, second);
  } catch (error) {
    console.error(`UI preparation failed: ${error.message}`);
    process.exitCode = 1;
  }
}
