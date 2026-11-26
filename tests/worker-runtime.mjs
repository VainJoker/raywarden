import { notifydo } from "./index.js";
import { accessToken, createRuntimeFixtures, USER, CIPHER, FILE, SEND } from "./runtime-fixture.mjs";
import { authChecks } from "./auth-runtime.mjs";
import { credentialsChecks } from "./credentials-runtime.mjs";
import { accountsChecks } from "./accounts-runtime.mjs";
import { vaultChecks } from "./vault-runtime.mjs";
import { runSendTests } from "./send-runtime.mjs";
import { platformChecks } from "./platform-runtime.mjs";

async function runSuite(state, ctx, setNotifyDo) {
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
    accessToken, USER, CIPHER, FILE, SEND, sql: state.storage.sql,
    notificationFetch: (f, request) => new notifydo(state, f.env).fetch(request),
  };
  const suites = [...authChecks, ...credentialsChecks, ...accountsChecks, ...vaultChecks, runSendTests, ...platformChecks];
  for (const run of suites) await run(suiteContext);
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
