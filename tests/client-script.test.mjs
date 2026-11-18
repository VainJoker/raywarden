import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import vm from "node:vm";
import test from "node:test";
const source = await readFile(new URL("../static/overrides/raywarden.js", import.meta.url), "utf8");
async function run(hash, status) {
  const urls = [], redirects = [];
  vm.runInNewContext(source, { location: { hash, pathname: "/", search: "", replace: url => redirects.push(url) },
    window: { addEventListener() {} }, fetch: async url => { urls.push(url); return { ok:true, json: async () => status }; } });
  await new Promise(resolve => setImmediate(resolve));
  return { urls, redirects };
}
test("Send verification preserves encryption key only in a browser fragment", async () => {
  const { urls, redirects } = await run("#/send/access-id/encryption-key", { enabled:true, valid:false });
  assert.deepEqual(urls, ["/api/send-verify/status"]);
  assert.equal(redirects.length, 1);
  const target = new URL(redirects[0], "https://vault.test");
  assert.equal(target.search, "");
  assert.equal(decodeURIComponent(target.hash.slice(1)), "/#/send/access-id/encryption-key");
});
test("verified, disabled and ordinary vault pages do not redirect", async () => {
  assert.equal((await run("#/send/id/key", {enabled:true,valid:true})).redirects.length,0);
  assert.equal((await run("#/send/id/key", {enabled:false,valid:false})).redirects.length,0);
  assert.deepEqual((await run("#/vault", {enabled:true,valid:false})).urls,[]);
});
