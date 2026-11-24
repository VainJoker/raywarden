import RustWorker, { heavydo, notifydo } from "./index.js";
import { equal } from "./runtime-tools.mjs";
import { accessToken, createRuntimeFixtures, USER, CIPHER, FILE, SEND, NOW } from "./runtime-fixture.mjs";
import { runAuthTests } from "./auth-runtime.mjs";
import { runCredentialTests } from "./credentials-runtime.mjs";
import { runAccountTests } from "./accounts-runtime.mjs";
import { runVaultTests } from "./vault-runtime.mjs";
import { runSendTests } from "./send-runtime.mjs";
import { runPlatformTests } from "./platform-runtime.mjs";

async function runSuite(state, ctx, setNotifyDo) {
  equal(typeof RustWorker, "function", "default Worker export");
  equal(typeof heavydo, "function", "heavydo export");
  equal(typeof notifydo, "function", "notifydo export");

  const fixtures = createRuntimeFixtures(state, ctx);
  let passed = 0;
  const failed = [];
  async function check(name, run) {
    try {
      await run();
      passed++;
      console.log(`PASS ${name}`);
    } catch (error) {
      failed.push(name);
      console.error(`FAIL ${name}: ${error.stack ?? error}`);
      const recentSqlFailure = fixtures.lastSqlFailure;
      if (recentSqlFailure) console.error("Most recent SQL boundary failure:", JSON.stringify(recentSqlFailure));
    }
  }
  // Each fixture resets the same temporary database, so run suites serially.
  const suiteContext = {
    fixture: fixtures.fixture, check, state, setNotifyDo, ctx,
    attachmentUploadFixture: fixtures.attachmentUploadFixture,
    kvFixture: fixtures.kvFixture,
    accessToken, USER, CIPHER, FILE, SEND, NOW, sql: state.storage.sql,
    notificationFetch: (f, request) => new notifydo(state, f.env).fetch(request),
  };
  await runAuthTests(suiteContext);
  await runCredentialTests(suiteContext);
  await runAccountTests(suiteContext);
  await runVaultTests(suiteContext);
  await runSendTests(suiteContext);
  await runPlatformTests(suiteContext);
  console.log(`Compiled Rust Worker runtime: ${passed} checks passed`);
  if (failed.length) throw new Error(`${failed.length} runtime checks failed: ${failed.join("; ")}`);
}

export class SqlRuntime {
  constructor(ctx) { this.ctx = ctx; }
  async fetch() {
    const pending = [];
    await runSuite(this.ctx, { waitUntil(promise) { pending.push(promise); } }, notify => { this.notify = notify; });
    await Promise.all(pending);
    return new Response("Runtime suite passed");
  }
  alarm() { return this.notify?.alarm(); }
  webSocketClose(socket, code, reason, wasClean) {
    return this.notify?.webSocketClose(socket, code, reason, wasClean);
  }
}
export default { async test(_controller, bindings) {
  const response = await bindings.SQL.get(bindings.SQL.idFromName("runtime")).fetch("https://test/");
  if (!response.ok) throw new Error(await response.text());
} };
