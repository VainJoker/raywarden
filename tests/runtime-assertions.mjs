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
