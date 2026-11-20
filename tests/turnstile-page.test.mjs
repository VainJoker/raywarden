import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';

const html = await readFile(new URL('../static/turnstile-verify.html', import.meta.url), 'utf8');
const source = html.match(/<script>([\s\S]*?)<\/script>/)[1];
function navigation(fragment, search = '') {
  const cleaned = [];
  const context = {
    URL, URLSearchParams,
    location: { hash: fragment, search, pathname: '/send-verify', origin: 'https://vault.example' },
    history: { replaceState(_state, _title, url) { cleaned.push(url); } },
  };
  vm.createContext(context);
  vm.runInContext(`${source}\n;globalThis.result = target;`, context);
  return { target: context.result, cleaned };
}

test('encrypted Send return paths remain in fragments and are removed before widget load', () => {
  const path = '/#/send/uuid/decryption-key';
  const result = navigation(`#${encodeURIComponent(path)}`);
  assert.equal(result.target, `https://vault.example${path}`);
  assert.deepEqual(result.cleaned, ['/send-verify']);
});

test('external return addresses cannot turn verification into an open redirect', () => {
  for (const target of ['https://evil.example/steal', '//evil.example/steal', 'javascript:alert(1)']) {
    assert.equal(navigation(`#${encodeURIComponent(target)}`).target, '/');
  }
});

test('query return parameters do not carry or select the decryption key', () => {
  const result = navigation('', '?return=https://evil.example/steal');
  assert.equal(result.target, 'https://vault.example/');
});

test('malformed fragment encoding returns safely to the vault', () => {
  assert.equal(navigation('#%bad%').target, 'https://vault.example/');
});
