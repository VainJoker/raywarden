import RustWorker, { heavydo, notifydo } from "./index.js";
import { runAccountCompatibility } from "./account-runtime.mjs";
import { runSendCompatibility } from "./send-runtime.mjs";
import { runTwoFactorCompatibility } from "./two-factor-runtime.mjs";
import { runJwtCompatibility } from "./jwt-runtime.mjs";
import { runConfigurationCompatibility } from "./config-runtime.mjs";
import { runPresentationCompatibility } from "./presentation-runtime.mjs";
import { runAdminNotificationCompatibility } from "./admin-notify-runtime.mjs";
import { runSetupCompatibility } from "./setup-runtime.mjs";
import { runPasswordCompatibility } from "./password-runtime.mjs";
import { runPreloginCompatibility } from "./prelogin-runtime.mjs";
import { runRecoveryCompatibility } from "./recovery-runtime.mjs";
import { runSetPasswordCompatibility } from "./set-password-runtime.mjs";
import { runAuthSessionChecks } from "./auth-session-runtime.mjs";
import { runSendParityCompatibility } from "./send-parity-runtime.mjs";
import { runRouteParityCompatibility } from "./route-parity-runtime.mjs";
import { runAccountSettingsChecks } from "./account-settings-runtime.mjs";
import { runProtectedActionCompatibility } from "./protected-action-runtime.mjs";
import { runPersonalVaultCompatibility } from "./personal-vault-runtime.mjs";
import { runSecurityHeadersCompatibility } from "./security-headers-runtime.mjs";
import { runRateLimitChecks } from "./rate-limit-runtime.mjs";

import { equal } from "./runtime-assertions.mjs";
import { accessToken, createRuntimeFixtures, USER, CIPHER, FILE, SEND, NOW } from "./runtime-fixture.mjs";
import { runEdgeChecks } from "./edge-runtime.mjs";
import { runStorageChecks } from "./storage-runtime.mjs";
import { runVaultChecks } from "./vault-runtime.mjs";

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
    fixture: fixtures.fixture, check, accessToken, USER, CIPHER, FILE, SEND, NOW, sql: state.storage.sql,
    notificationFetch: (f, request) => new notifydo(state, f.env).fetch(request),
  };
  await runEdgeChecks({ ...suiteContext, state, setNotifyDo });
  await runStorageChecks({ ...suiteContext, ctx, attachmentUploadFixture: fixtures.attachmentUploadFixture, kvFixture: fixtures.kvFixture });
  await runVaultChecks(suiteContext);
  await runAccountCompatibility(suiteContext);
  await runSendCompatibility(suiteContext);
  await runTwoFactorCompatibility(suiteContext);
  await runJwtCompatibility(suiteContext);
  await runConfigurationCompatibility(suiteContext);
  await runPresentationCompatibility(suiteContext);
  await runAdminNotificationCompatibility(suiteContext);
  await runSetupCompatibility(suiteContext);
  await runPasswordCompatibility(suiteContext);
  await runPreloginCompatibility(suiteContext);
  await runRecoveryCompatibility(suiteContext);
  await runSetPasswordCompatibility(suiteContext);
  await runAuthSessionChecks(suiteContext);
  await runSendParityCompatibility(suiteContext);
  await runRouteParityCompatibility(suiteContext);
  await runAccountSettingsChecks(suiteContext);
  await runProtectedActionCompatibility(suiteContext);
  await runPersonalVaultCompatibility(suiteContext);
  await runSecurityHeadersCompatibility(suiteContext);
  await runRateLimitChecks(suiteContext);
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
