import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const html = await readFile(new URL("../static/demo.html", import.meta.url), "utf8");
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
const EMAIL = "owner@example.test", PASSWORD = "test password", ITERATIONS = 100;

async function fixture(override) {
  const elements = new Map(), requests = [];
  const element = id => {
    if (!elements.has(id)) elements.set(id, { value: "", textContent: "", handlers: new Map(),
      addEventListener(name, handler) { this.handlers.set(name, handler); } });
    return elements.get(id);
  };
  const json = (body, status = 200) => new Response(JSON.stringify(body), { status });
  let wrapped, token, profile;
  const context = vm.createContext({ TextEncoder, URLSearchParams, Uint8Array, crypto: webcrypto, atob, btoa,
    document: { getElementById: element }, console: { log() { throw new Error("demo logged credentials"); } },
    fetch: async (path, init = {}) => {
      assert.match(path, /^\/(?!\/)/);
      assert.equal(init.credentials, "same-origin");
      const request = { path, ...init, body: init.headers?.["Content-Type"] === "application/json" ? JSON.parse(init.body) : init.body };
      requests.push(request);
      const custom = await override?.(request, { json, token, profile });
      if (custom) return custom;
      if (path === "/api/accounts/prelogin") return json({ kdf: 0, kdfIterations: ITERATIONS, salt: EMAIL });
      if (path === "/identity/connect/token") return json(token);
      if (path === "/api/accounts/profile") return json(profile);
      if (path === "/api/d1/usage") return json({ totalBytes: 42, items: [{ name: "Ciphers", bytes: 42 }] });
      return json({});
    },
  });
  vm.runInContext(script, context);
  const master = await context.deriveMasterKey(EMAIL, PASSWORD, ITERATIONS);
  const stretched = await context.stretchMasterKey(master);
  const plain = new Uint8Array(64).fill(42); plain[63] = 254;
  wrapped = await context.encryptEncString(plain, stretched.encKey, stretched.macKey, false);
  const keys = { publicKeyEncryptionKeyPair: { wrappedPrivateKey: "2.private" }, signatureKeyPair: null, securityState: null };
  token = { access_token: "sensitive-access-token", refresh_token: "sensitive-refresh-token", Key: wrapped,
    PrivateKey: "2.private", AccountKeys: keys, Kdf: 0, KdfIterations: ITERATIONS, expires_in: 3600 };
  profile = { key: wrapped, privateKey: "2.private", accountKeys: keys, kdf: 0, kdfIterations: ITERATIONS };
  const set = (id, value) => { element(id).value = value; };
  const click = id => element(id).handlers.get("click")({ preventDefault() {} });
  const text = id => element(id).textContent;
  const noCredentialOutput = () => {
    for (const value of elements.values()) {
      assert.ok(!value.textContent.includes(token.access_token));
      assert.ok(!value.textContent.includes(token.refresh_token));
      for (const request of requests.filter(item => item.path === "/identity/connect/token")) {
        assert.ok(!value.textContent.includes(new URLSearchParams(request.body).get("password")));
      }
    }
  };
  return { context, requests, token, profile, plain, set, click, text, element, noCredentialOutput };
}

test("demo rejects Argon2, invalid KDF and unsupported V2 before account mutation", async () => {
  for (const kdf of [1, 7, null]) {
    const f = await fixture((request, { json }) => request.path === "/api/accounts/prelogin" ? json({ kdf, kdfIterations: ITERATIONS }) : null);
    f.set("email", EMAIL); f.set("oldPassword", PASSWORD); f.set("newPassword", "replacement");
    await f.click("submit");
    assert.match(f.text("result"), /official client/);
    assert.deepEqual(f.requests.map(request => request.path), ["/api/accounts/prelogin"]);
  }
  const f = await fixture();
  f.token.AccountKeys.securityState = { securityVersion: 2 };
  f.set("email", EMAIL); f.set("oldPassword", PASSWORD); f.set("newPassword", "replacement");
  await f.click("submit");
  assert.match(f.text("result"), /official client/);
  assert.ok(!f.requests.some(request => request.path === "/api/accounts/password"));
});

test("demo login sends a stable page device and optional existing TOTP without rendering credentials", async () => {
  const f = await fixture();
  f.set("loginTotp", "123456");
  await f.context.login(EMAIL, "sensitive-password-hash", ITERATIONS);
  await f.context.login(EMAIL, "sensitive-password-hash", ITERATIONS);
  const calls = f.requests.filter(request => request.path === "/identity/connect/token");
  const first = new URLSearchParams(calls[0].body), second = new URLSearchParams(calls[1].body);
  assert.match(first.get("deviceIdentifier"), /^[0-9a-f-]{36}$/);
  assert.equal(first.get("deviceIdentifier"), second.get("deviceIdentifier"));
  assert.equal(first.get("twoFactorProvider"), "0"); assert.equal(first.get("twoFactorToken"), "123456");
  assert.equal(second.has("twoFactorToken"), false);
  assert.equal(calls[0].headers["Bitwarden-Client-Version"], "2026.7.0");
  f.noCredentialOutput();
});

test("password change posts the current key DTO and preserves the existing user key crypto", async () => {
  const f = await fixture();
  f.set("email", EMAIL); f.set("oldPassword", PASSWORD); f.set("newPassword", "replacement");
  await f.click("submit");
  const request = f.requests.find(item => item.path === "/api/accounts/password");
  assert.ok(request, f.text("result")); assert.equal(request.method, "POST");
  assert.equal(request.headers.Authorization, `Bearer ${f.token.access_token}`);
  assert.equal(typeof request.body.key, "string"); assert.equal("userSymmetricKey" in request.body, false);
  const key = await f.context.deriveMasterKey(EMAIL, "replacement", ITERATIONS);
  const stretched = await f.context.stretchMasterKey(key);
  const decrypted = await f.context.decryptEncString(request.body.key, stretched.encKey, stretched.macKey);
  assert.deepEqual([...decrypted.plainBytes], [...f.plain]);
  f.noCredentialOutput();
});

test("email change sends the gateway code first and commits with the same session and explicit token", async () => {
  const f = await fixture();
  f.set("emailCurrent", EMAIL); f.set("emailNew", "new@example.test"); f.set("emailPassword", PASSWORD);
  await f.click("submitEmail");
  assert.match(f.text("resultEmail"), /Send the verification code.*first/); assert.equal(f.requests.length, 0);
  await f.click("sendEmailToken");
  const send = f.requests.find(request => request.path === "/api/accounts/email-token");
  assert.ok(send, f.text("resultEmail")); assert.equal(send.method, "POST");
  assert.equal(send.body.newEmail, "new@example.test");
  f.set("emailCode", "012345"); await f.click("submitEmail");
  const change = f.requests.find(request => request.path === "/api/accounts/email");
  assert.ok(change, f.text("resultEmail")); assert.equal(change.method, "POST");
  assert.equal(change.body.token, "012345"); assert.equal(change.headers.Authorization, send.headers.Authorization);
  assert.equal(change.body.masterPasswordHash, send.body.masterPasswordHash);
  assert.equal(f.requests.filter(request => request.path === "/identity/connect/token").length, 1);
  const key = await f.context.deriveMasterKey("new@example.test", PASSWORD, ITERATIONS);
  const stretched = await f.context.stretchMasterKey(key);
  assert.deepEqual([...(await f.context.decryptEncString(change.body.key, stretched.encKey, stretched.macKey)).plainBytes], [...f.plain]);
  f.noCredentialOutput();
});

test("TOTP uses password-authenticated setup and a fresh enabled-state proof when disabling", async () => {
  let enabled = false, proofNumber = 0;
  const f = await fixture((request, { json }) => {
    if (request.path === "/api/two-factor/get-authenticator") {
      assert.equal(typeof request.body.masterPasswordHash, "string");
      return json({ enabled, key: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", userVerificationToken: `proof-${++proofNumber}` });
    }
    if (request.path === "/api/two-factor/authenticator") {
      assert.equal(request.body.key, "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP");
      if (request.method === "POST") {
        assert.equal(request.body.token, "123456"); assert.equal(request.body.userVerificationToken, "proof-1"); enabled = true;
      } else {
        assert.equal(request.method, "DELETE"); assert.equal(request.body.type, 0);
        assert.equal(request.body.userVerificationToken, "proof-2"); enabled = false;
      }
      return json({ enabled });
    }
    return null;
  });
  f.set("totpEmail", EMAIL); f.set("totpPassword", PASSWORD);
  await f.click("totpRequest"); assert.match(f.element("totpOtpauth").value, /^otpauth:\/\/totp\//);
  f.set("totpCode", "123456"); await f.click("totpEnable"); assert.equal(enabled, true);
  await f.click("totpDisable"); assert.equal(enabled, false); assert.equal(proofNumber, 2);
  assert.equal(f.requests.filter(request => request.path === "/identity/connect/token").length, 1);
  assert.ok(!f.requests.some(request => /authenticator\/(?:request|enable|disable)$/.test(request.path)));
  f.noCredentialOutput();
});

test("usage requires a bearer and server errors never echo response credentials", async () => {
  const f = await fixture();
  f.set("usageEmail", EMAIL); f.set("usagePassword", PASSWORD); await f.click("usageRefresh");
  const usage = f.requests.find(request => request.path === "/api/d1/usage");
  assert.ok(usage, f.text("resultUsage")); assert.equal(usage.method, "GET");
  assert.equal(usage.headers.Authorization, `Bearer ${f.token.access_token}`);
  const failure = await fixture((request, { json }) => request.path === "/api/accounts/prelogin" ? json({ error_description: "sensitive-password-hash sensitive-access-token" }, 500) : null);
  failure.set("usageEmail", EMAIL); failure.set("usagePassword", PASSWORD); await failure.click("usageRefresh");
  assert.match(failure.text("resultUsage"), /HTTP 500/); failure.noCredentialOutput();
  assert.ok(!failure.text("resultUsage").includes("sensitive-password-hash"));
});
