export function equal(actual, expected, label = "value") {
  if (actual !== expected) throw new Error(`${label}: expected ${expected}, received ${actual}`);
}

export function ok(condition, label) {
  if (!condition) throw new Error(label);
}

export function sameBytes(actual, expected) {
  equal(actual.length, expected.length, "byte length");
  for (let i = 0; i < expected.length; i++) equal(actual[i], expected[i], `byte ${i}`);
}

export async function expectStatus(response, expected, label = "HTTP response") {
  if (response.status !== expected) {
    throw new Error(`${label}: expected ${expected}, received ${response.status}: ${await response.text()}`);
  }
  return response;
}

export async function expectJson(response, expected, label) {
  await expectStatus(response, expected, label);
  return response.json();
}

export async function expectJsonOrEmpty(response, expected, label) {
  await expectStatus(response, expected, label);
  const body = await response.text();
  return body ? JSON.parse(body) : null;
}

export function bearerJsonHeaders(token) {
  return { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
}

export function assertDownloadSecurityHeaders(response, disposition = "attachment") {
  for (const [name, expected] of [
    ["content-type", "application/octet-stream"],
    ["content-disposition", disposition],
    ["content-security-policy", "default-src 'none'; sandbox"],
    ["x-content-type-options", "nosniff"],
    ["referrer-policy", "no-referrer"],
    ["x-robots-tag", "noindex, nofollow"],
    ["cache-control", "private, no-store"],
  ]) {
    equal(response.headers.get(name), expected, `download ${name}`);
  }
}

/** Test-client OAuth requests and authentication data built independently of Rust. */
export function oauthToken(fixture, fields, headers = {}) {
  return fixture.fetch("/identity/connect/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", ...headers },
    body: fields instanceof URLSearchParams ? fields : new URLSearchParams(fields),
  });
}

const encoder = new TextEncoder();
const jwtFields = ["access_secret", "refresh_secret"];
export const fromBase64Url = value => Uint8Array.from(atob(value.replaceAll("-", "+").replaceAll("_", "/")), byte => byte.charCodeAt(0));
export const toBase64Url = value => btoa(String.fromCharCode(...value)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
const fixtureContext = field => encoder.encode(`raywarden/jwt-key-encryption/v1/global/${field}`);
async function fixtureRootKey(rootSecret) {
  const raw = fromBase64Url(rootSecret);
  if (raw.length !== 32 || toBase64Url(raw) !== rootSecret) throw new Error("Invalid fixture KEY_ENCRYPTION_KEY");
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}
function fixtureIsWrapped(keys) {
  for (const field of jwtFields) if (typeof keys[field] !== "string" || !keys[field].trim()) throw new Error(`Invalid fixture ${field}`);
  const wrapped = jwtFields.map(field => keys[field].startsWith("v1."));
  if (wrapped[0] !== wrapped[1]) throw new Error("Mixed fixture JWT envelope formats");
  if (!wrapped[0] && jwtFields.some(field => /^v\d+\./.test(keys[field]))) throw new Error("Unsupported fixture JWT envelope version");
  return wrapped[0];
}

/** Independently decode production AES-GCM envelopes, or a fresh legacy fixture. */
export async function openFixtureJwtKeys(keys, rootSecret) {
  if (!fixtureIsWrapped(keys)) return { access_secret: keys.access_secret, refresh_secret: keys.refresh_secret };
  const result = {}, key = await fixtureRootKey(rootSecret);
  for (const field of jwtFields) {
    const encoded = keys[field].slice(3), packed = fromBase64Url(encoded);
    if (packed.length < 29 || toBase64Url(packed) !== encoded) throw new Error(`${field} envelope is malformed`);
    const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: packed.subarray(0, 12), additionalData: fixtureContext(field) }, key, packed.subarray(12));
    result[field] = new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
    if (!result[field].trim()) throw new Error(`${field} envelope contains an empty key`);
  }
  return result;
}

/** Produce test-controlled envelopes using WebCrypto, independently of Rust. */
export async function wrapFixtureJwtKeys(keys, rootSecret) {
  if (fixtureIsWrapped(keys)) throw new Error("Fixture JWT keys are already wrapped");
  const result = {}, key = await fixtureRootKey(rootSecret);
  for (const field of jwtFields) {
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: fixtureContext(field) }, key, encoder.encode(keys[field])));
    const packed = new Uint8Array(12 + encrypted.length); packed.set(nonce); packed.set(encrypted, 12);
    result[field] = `v1.${toBase64Url(packed)}`;
  }
  return result;
}

export async function fixtureAccessSecret(sql, rootSecret) {
  const keys = sql.exec("SELECT access_secret,refresh_secret FROM jwt_keys WHERE id='global'").one();
  return (await openFixtureJwtKeys(keys, rootSecret)).access_secret;
}

export async function emailCodeHash(secret, { owner, purpose, recipient, context, code }) {
  const parts = [owner, purpose, recipient, context, code].map(part => encoder.encode(part));
  const message = new Uint8Array(parts.reduce((total, bytes) => total + 8 + bytes.length, 0));
  const lengths = new DataView(message.buffer);
  let offset = 0;
  for (const bytes of parts) {
    lengths.setBigUint64(offset, BigInt(bytes.length), false);
    message.set(bytes, offset + 8);
    offset += 8 + bytes.length;
  }
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, message));
  return Array.from(digest, byte => byte.toString(16).padStart(2, "0")).join("");
}

export async function totp(secret, step = Math.floor(Date.now() / 30000)) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let accumulator = 0, bits = 0;
  const bytes = [];
  for (const char of secret.toUpperCase().replace(/=+$/, "")) {
    const value = alphabet.indexOf(char);
    if (value < 0) throw new Error("Invalid Base32 key in TOTP fixture");
    accumulator = (accumulator << 5) | value;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((accumulator >>> bits) & 255);
    }
  }
  const counter = new Uint8Array(8);
  new DataView(counter.buffer).setBigUint64(0, BigInt(step), false);
  const key = await crypto.subtle.importKey("raw", new Uint8Array(bytes), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter));
  const offset = digest[digest.length - 1] & 15;
  const value = new DataView(digest.buffer).getUint32(offset, false) & 0x7fffffff;
  return String(value % 1000000).padStart(6, "0");
}
