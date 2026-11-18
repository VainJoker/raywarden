import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const [rate, access, token, controller, identity, routes] = await Promise.all([
  "api/service/rate.rs", "send/access.rs", "send/token.rs", "send/http.rs",
  "api/controller/identity.rs", "send/routes.rs",
].map((path) => readFile(new URL(`../src/${path}`, import.meta.url), "utf8")));

// These assertions check the real Rust call graph, without substituting a
// second implementation of Worker bindings or anonymous Send authorization.
function functionSource(source, name) {
  const start = source.indexOf(`async fn ${name}(`);
  assert.notEqual(start, -1, `missing ${name}`);
  const rest = source.slice(start);
  const next = rest.slice(1).search(/\n(?:pub )?async fn /);
  return next === -1 ? rest : rest.slice(0, next + 1);
}

test("Send and protected-account checks select independent bindings in the same backend", () => {
  assert.match(rate, /const LOGIN_RATE_LIMITER: &str = "LOGIN_RATE_LIMITER"/);
  assert.match(rate, /const SEND_ACCESS_RATE_LIMITER: &str = "SEND_ACCESS_RATE_LIMITER"/);
  assert.match(functionSource(rate, "check_rate_limit"), /check_rate_limit_binding\(state, rate_limit_key, LOGIN_RATE_LIMITER\)/);
  assert.match(functionSource(rate, "check_send_access_rate_limit"), /check_rate_limit_binding\(state, rate_limit_key, SEND_ACCESS_RATE_LIMITER\)/);
  assert.match(functionSource(rate, "check_rate_limit_binding"), /state\.env\.rate_limiter\(binding\)/);
});

test("legacy Send and both identity grants share the dedicated authorization limiter", () => {
  const authorization = functionSource(access, "authorize_anonymous");
  assert.match(authorization, /rate::check_send_access_rate_limit\(/);
  assert.doesNotMatch(authorization, /rate::check_rate_limit\(/);
  assert.match(authorization, /format!\("send:\{\}:\{\}", send\.id, rate::client_ip\(headers\)\)/);
  assert.ok(authorization.indexOf("check_send_access_rate_limit") < authorization.indexOf("send.check_password"));
  for (const handler of ["access_send", "access_file_send"]) {
    assert.match(functionSource(controller, handler), /access::authorize_anonymous\(/);
  }
  assert.match(functionSource(token, "issue_access_token"), /authorize_anonymous\(state, headers, &send, password\)/);
  assert.match(identity, /"send_access" \| "access_token" => \{[\s\S]*?send::issue_access_token\(/);
  assert.match(routes, /"\/api\/sends\/access\/\{access_id\}", post\(http::access_send\)/);
  assert.match(routes, /"\/api\/sends\/\{id\}\/access\/file\/\{file_id\}",[\s\S]*?post\(http::access_file_send\)/);
  for (const handler of ["access_send_with_token", "access_file_send_with_token"]) {
    assert.match(functionSource(controller, handler), /access::send_from_access_token\(/);
  }
});
