import { openFixtureJwtKeys, wrapFixtureJwtKeys } from "./jwt-runtime.mjs";

/** Stable unknown-email KDF responses through compiled Rust and real SQLite. */
export async function runPreloginCompatibility({ fixture, check, sql }) {
  const aliases = [
    "/api/accounts/prelogin", "/api/accounts/prelogin/password",
    "/identity/accounts/prelogin", "/identity/accounts/prelogin/password",
  ];
  const equal = (actual, expected, label = "value") => {
    if (actual !== expected) throw new Error(`${label}: expected ${expected}, received ${actual}`);
  };
  const expectStatus = async (response, expected) => {
    if (response.status !== expected) throw new Error(`Expected HTTP ${expected}, received ${response.status}: ${await response.text()}`);
    return response;
  };
  const request = (f, email, path = aliases[0]) => f.fetch(path, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
  });
  const prelogin = async (f, email, path) => (await expectStatus(await request(f, email, path), 200)).json();
  const users = () => JSON.stringify(sql.exec("SELECT * FROM users ORDER BY id").toArray());
  const settings = (body, [type, iterations, memory, parallelism], email) => {
    equal(body.kdf, type, "top-level KDF type");
    equal(body.kdfIterations, iterations, "top-level iterations");
    equal(body.kdfMemory ?? null, memory, "top-level memory");
    equal(body.kdfParallelism ?? null, parallelism, "top-level parallelism");
    equal(body.kdfSettings.kdfType, type, "nested KDF type");
    equal(body.kdfSettings.iterations, iterations, "nested iterations");
    equal(body.kdfSettings.memory, memory, "nested memory");
    equal(body.kdfSettings.parallelism, parallelism, "nested parallelism");
    equal(body.salt, email, "normalized salt");
  };

  await check("prelogin keeps real account KDF parameters on every alias without credential writes", async () => {
    const f = fixture();
    const email = "owner@example.test";
    for (const values of [[0, 750000, null, null], [1, 4, 96, 2]]) {
      sql.exec("UPDATE users SET kdf_type=?,kdf_iterations=?,kdf_memory=?,kdf_parallelism=? WHERE email=?", ...values, email);
      const before = users();
      for (const path of aliases) settings(await prelogin(f, " Owner@Example.TEST ", path), values, email);
      equal(users(), before, "stored account and credential state");
    }
  });

  await check("unknown prelogin stays stable across aliases, normalized emails and independent requests", async () => {
    const f = fixture({ empty: true });
    const before = users();
    const first = await prelogin(f, "unknown@example.test");
    // Independent HMAC vector: digest 76df0f736cbc9c66 selects bucket 1
    // with the fixture's persisted key. Truncating to WASM32 first selects 6.
    settings(first, [1, 3, 64, 4], "unknown@example.test");
    for (const path of aliases) {
      const response = await prelogin(f, " Unknown@Example.TEST ", path);
      equal(JSON.stringify(response), JSON.stringify(first), "stable prelogin response");
    }
    f.env.JWT_SECRET = "obsolete-legacy-binding-must-not-select-the-bucket";
    equal(JSON.stringify(await prelogin(f, "unknown@example.test")), JSON.stringify(first), "D1-owned key remains authoritative");
    equal(users(), before, "unknown prelogin cannot create accounts");
  });

  await check("unknown prelogin uses the persisted secret and never changes an existing account's settings", async () => {
    const f = fixture();
    const real = await prelogin(f, "owner@example.test");
    const before = users();
    const first = await prelogin(f, "unknown@example.test");
    const current = await openFixtureJwtKeys(
      sql.exec("SELECT access_secret,refresh_secret FROM jwt_keys WHERE id='global'").one(), f.env.KEY_ENCRYPTION_KEY);
    const rotated = await wrapFixtureJwtKeys({ ...current, access_secret: "rotated-prelogin-runtime-secret" }, f.env.KEY_ENCRYPTION_KEY);
    sql.exec("UPDATE jwt_keys SET access_secret=?,refresh_secret=? WHERE id='global'", rotated.access_secret, rotated.refresh_secret);
    const changed = await prelogin(f, "unknown@example.test");
    settings(changed, [0, 5000, null, null], "unknown@example.test");
    if (JSON.stringify(first) === JSON.stringify(changed)) throw new Error("persisted key did not affect the selected settings");
    equal(JSON.stringify(await prelogin(f, "owner@example.test")), JSON.stringify(real), "real account parameters ignore decoy key selection");
    equal(users(), before, "stored account and credential state");
  });

  await check("a failed prelogin database query fails instead of becoming an unknown-email response", async () => {
    const f = fixture({ empty: true });
    sql.exec("DROP TABLE users");
    for (const path of aliases) await expectStatus(await request(f, "unknown@example.test", path), 500);
  });
}
