import { assertDownloadSecurityHeaders, bearerJsonHeaders, equal, expectJson, expectStatus } from "./runtime-assertions.mjs";
import { oauthToken } from "./runtime-auth.mjs";

/** Two independently authenticated sessions using real client-side crypto.
 * Runs production WASM/SQL with isolated object-storage bindings. This is a
 * server round trip, not an official-client or real-cloud acceptance test.
 */
export async function runPersonalVaultCompatibility({ fixture, check }) {
  const encoder = new TextEncoder(), decoder = new TextDecoder();
  const json = async response => expectJson(await response, 200);
  const base64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes)));
  const unbase64 = text => Uint8Array.from(atob(text), char => char.charCodeAt(0));
  const rawKey = () => crypto.getRandomValues(new Uint8Array(64));
  async function seal(raw, plaintext) {
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const aes = await crypto.subtle.importKey("raw", raw.slice(0, 32), "AES-CBC", false, ["encrypt"]);
    const mac = await crypto.subtle.importKey("raw", raw.slice(32), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-CBC", iv }, aes, encoder.encode(plaintext)));
    const authenticated = new Uint8Array(iv.length + encrypted.length); authenticated.set(iv); authenticated.set(encrypted, iv.length);
    return `2.${base64(iv)}|${base64(encrypted)}|${base64(await crypto.subtle.sign("HMAC", mac, authenticated))}`;
  }
  async function open(raw, ciphertext) {
    equal(ciphertext.slice(0, 2), "2.", "encryption type");
    const [iv, encrypted, signature] = ciphertext.slice(2).split("|").map(unbase64);
    const authenticated = new Uint8Array(iv.length + encrypted.length); authenticated.set(iv); authenticated.set(encrypted, iv.length);
    const mac = await crypto.subtle.importKey("raw", raw.slice(32), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
    equal(await crypto.subtle.verify("HMAC", mac, signature, authenticated), true, "ciphertext authentication");
    const aes = await crypto.subtle.importKey("raw", raw.slice(0, 32), "AES-CBC", false, ["decrypt"]);
    return decoder.decode(await crypto.subtle.decrypt({ name: "AES-CBC", iv }, aes, encrypted));
  }
  const pathOf = value => { const url = new URL(value, "https://vault.test"); return url.pathname + url.search; };
  const request = (f, tokens, path, body, method = "POST") => f.fetch(path, {
    method, headers: bearerJsonHeaders(tokens.access_token), ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const login = (f, password, device) => json(oauthToken(f, {
    grant_type: "password", username: "personal@example.test", password,
    deviceIdentifier: device, deviceName: device, deviceType: "14",
  }, { "Bitwarden-Client-Version": "2026.10.1", "device-type": "14" }));
  const sync = (f, tokens) => json(request(f, tokens, "/api/sync?excludeDomains=true", undefined, "GET"));
  async function bootstrap() {
    const f = fixture({ empty: true });
    f.env.ALLOWED_EMAILS = "personal@example.test";
    f.env.OWNER_SETUP_TOKEN = "isolated-personal-vault-owner-authorization";
    const wrapping = rawKey(), userKey = rawKey();
    const authentication = base64(crypto.getRandomValues(new Uint8Array(32)));
    const wrapped = await seal(wrapping, base64(userKey));
    await expectStatus(await f.fetch("/api/accounts/register", { method: "POST", headers: {
      "Content-Type": "application/json", "X-Raywarden-Setup-Token": f.env.OWNER_SETUP_TOKEN,
    }, body: JSON.stringify({ email: f.env.ALLOWED_EMAILS, masterPasswordHash: authentication, key: wrapped,
      keys: { publicKey: "isolated-public-key", encryptedPrivateKey: await seal(userKey, "isolated-private-key") }, kdf: 0, kdfIterations: 600000 }) }), 200);
    const first = await login(f, authentication, "personal-first-device");
    const second = await login(f, authentication, "personal-second-device");
    equal(first.access_token === second.access_token, false, "independent sessions");
    return { f, first, second, userKey, wrapping, authentication };
  }

  await check("two login sessions decrypt each other's edits and old ciphertext after password rewrapping", async () => {
    const { f, first, second, userKey, authentication } = await bootstrap();
    const folder = await json(request(f, first, "/api/folders", { name: await seal(userKey, "Personal folder") }));
    const item = await json(request(f, first, "/api/ciphers", { type: 1, name: await seal(userKey, "Personal login"),
      folderId: folder.id, login: { username: await seal(userKey, "roundtrip-user"), password: await seal(userKey, "roundtrip-password") } }));
    let snapshot = await sync(f, second), remote = snapshot.ciphers.find(cipher => cipher.id === item.id);
    equal(await open(userKey, remote.login.password), "roundtrip-password");
    equal(await open(userKey, snapshot.folders[0].name), "Personal folder");
    equal(snapshot.policiesNew.length, 0);
    await json(request(f, second, `/api/ciphers/${item.id}`, { ...remote, name: await seal(userKey, "Edited on second device"), lastKnownRevisionDate: remote.revisionDate }, "PUT"));
    remote = (await sync(f, first)).ciphers.find(cipher => cipher.id === item.id);
    equal(await open(userKey, remote.name), "Edited on second device");
    equal(await open(userKey, remote.login.username), "roundtrip-user");
    const nextAuthentication = base64(crypto.getRandomValues(new Uint8Array(32))), newWrapping = rawKey();
    await expectStatus(await request(f, second, "/api/accounts/password", { masterPasswordHash: authentication,
      newMasterPasswordHash: nextAuthentication, key: await seal(newWrapping, base64(userKey)) }), 200);
    for (const old of [first, second]) await expectStatus(await request(f, old, "/api/accounts/profile", undefined, "GET"), 401);
    const renewed = await login(f, nextAuthentication, "personal-first-device");
    equal(await open(newWrapping, renewed.Key), base64(userKey), "rewrapped user key");
    snapshot = await sync(f, renewed);
    equal(await open(userKey, snapshot.ciphers[0].login.password), "roundtrip-password");
    equal(await open(userKey, snapshot.ciphers[0].name), "Edited on second device");
    await expectStatus(await f.fetch("/api/sync"), 401);
  });

  await check("another session downloads encrypted attachments and anonymous recipients decrypt text and file Sends", async () => {
    const { f, first, second, userKey } = await bootstrap();
    const item = await json(request(f, first, "/api/ciphers", { type: 1, name: await seal(userKey, "With file"), login: {} }));
    const fileKey = rawKey(), ciphertext = await seal(fileKey, "roundtrip attachment bytes");
    const reserved = await json(request(f, first, `/api/ciphers/${item.id}/attachment/v2`, {
      key: await seal(userKey, base64(fileKey)), fileName: await seal(userKey, "example.txt"), fileSize: encoder.encode(ciphertext).length,
    }));
    await expectStatus(await f.fetch(pathOf(reserved.url), { method: "PUT", body: encoder.encode(ciphertext) }), 201);
    const remote = (await sync(f, second)).ciphers.find(cipher => cipher.id === item.id);
    const attachment = remote.attachments[0];
    equal(await open(userKey, attachment.fileName), "example.txt");
    const metadata = await json(request(f, second, `/api/ciphers/${item.id}/attachment/${attachment.id}`, undefined, "GET"));
    const attachmentResponse = await expectStatus(await f.fetch(pathOf(metadata.url)), 200);
    assertDownloadSecurityHeaders(attachmentResponse);
    const downloaded = decoder.decode(await attachmentResponse.arrayBuffer());
    equal(await open(unbase64(await open(userKey, attachment.key)), downloaded), "roundtrip attachment bytes");
    await expectStatus(await f.fetch(`/api/ciphers/${item.id}/attachment/${attachment.id}`), 401);
    const sendKey = rawKey(), deletionDate = new Date(Date.now() + 86400000).toISOString();
    const textSend = await json(request(f, first, "/api/sends", { type: 0, name: await seal(sendKey, "Shared text"),
      key: await seal(userKey, base64(sendKey)), deletionDate, text: { text: await seal(sendKey, "Anonymous text"), hidden: false } }));
    const received = await json(f.fetch(`/api/sends/access/${textSend.accessId}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" }));
    equal(await open(sendKey, received.text.text), "Anonymous text");
    const encryptedFile = encoder.encode(await seal(sendKey, "Anonymous file bytes"));
    const fileSend = await json(request(f, first, "/api/sends/file/v2", { type: 1, name: await seal(sendKey, "Shared file"),
      key: await seal(userKey, base64(sendKey)), deletionDate, fileLength: encryptedFile.length, file: { fileName: await seal(sendKey, "shared.txt") } }));
    await expectStatus(await f.fetch(pathOf(fileSend.url), { method: "PUT", body: encryptedFile }), 201);
    const shared = fileSend.sendResponse;
    const granted = await json(f.fetch(`/api/sends/${shared.id}/access/file/${shared.file.id}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" }));
    const sendResponse = await expectStatus(await f.fetch(pathOf(granted.url)), 200);
    assertDownloadSecurityHeaders(sendResponse, 'attachment; filename="send-file"');
    const bytes = decoder.decode(await sendResponse.arrayBuffer());
    equal(await open(sendKey, bytes), "Anonymous file bytes");
    equal((await sync(f, second)).sends.length, 2);
  });
}
