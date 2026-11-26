import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const origin = "https://vault.test";
const vaultScript = await readFile(new URL("../static/overrides/raywarden.js", import.meta.url), "utf8");
const verifyPage = await readFile(new URL("../static/turnstile-verify.html", import.meta.url), "utf8");
const verifyScript = verifyPage.match(/<script>([\s\S]*?)<\/script>/)[1];

async function visitVault(hash, status) {
  const requests = [], redirects = [];
  vm.runInNewContext(vaultScript, {
    location: { hash, pathname: "/", search: "", replace: url => redirects.push(url) },
    window: { addEventListener() {} },
    fetch: async url => {
      requests.push(url);
      return { ok: true, json: async () => status };
    },
  });
  await new Promise(resolve => setImmediate(resolve));
  return { requests, redirects };
}

function visitVerification(url) {
  const { hash, search, pathname, origin: pageOrigin } = new URL(url, origin);
  const cleaned = [];
  const target = vm.runInNewContext(`${verifyScript}\ntarget;`, {
    URL, URLSearchParams,
    location: { hash, search, pathname, origin: pageOrigin },
    history: { replaceState(_state, _title, path) { cleaned.push(path); } },
  });
  return { target, cleaned };
}

test("Send verification keeps the decryption key in the fragment through the round trip", async () => {
  const hash = "#/send/access-id/encryption-key";
  const { requests, redirects } = await visitVault(hash, { enabled: true, valid: false });
  assert.deepEqual(requests, ["/api/send-verify/status"]);
  assert.equal(redirects.length, 1);
  const verificationUrl = new URL(redirects[0], origin);
  assert.equal(verificationUrl.origin, origin);
  assert.equal(verificationUrl.pathname, "/send-verify");
  assert.equal(verificationUrl.search, "");
  assert.equal(decodeURIComponent(verificationUrl.hash.slice(1)), `/${hash}`);

  const { target, cleaned } = visitVerification(verificationUrl);
  assert.equal(target, `${origin}/${hash}`);
  assert.deepEqual(cleaned, ["/send-verify"]);
});

test("verified, disabled and ordinary vault pages do not redirect", async () => {
  const hash = "#/send/id/key";
  assert.deepEqual((await visitVault(hash, { enabled: true, valid: true })).redirects, []);
  assert.deepEqual((await visitVault(hash, { enabled: false, valid: false })).redirects, []);
  assert.deepEqual(await visitVault("#/vault", { enabled: true, valid: false }), { requests: [], redirects: [] });
});

test("external, query and malformed return addresses safely fall back to the vault root", () => {
  for (const target of ["https://evil.example/steal", "//evil.example/steal", "javascript:alert(1)"]) {
    assert.equal(visitVerification(`/send-verify#${encodeURIComponent(target)}`).target, "/");
  }
  assert.equal(visitVerification("/send-verify?return=https://evil.example/steal").target, `${origin}/`);
  assert.equal(visitVerification("/send-verify#%bad%").target, `${origin}/`);
});
