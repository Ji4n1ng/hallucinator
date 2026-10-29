// The browser client (static/e2e.js with static/noble.js) against Catelier's
// shared vectors (tests/e2e_vectors.json), on both backends: WebCrypto
// (`subtle`) and the vendored noble code (`noble`).
//
//   node tests/e2e-web.test.mjs        (cargo test runs it too, when node is installed)
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const crate = join(dirname(fileURLToPath(import.meta.url)), "..");
const vectors = JSON.parse(readFileSync(join(crate, "tests/e2e_vectors.json"), "utf8"));

// The page globals e2e.js expects. No server: /api/health fails, so it stays plain.
globalThis.window = globalThis;
globalThis.location = { origin: "http://test.invalid", href: "http://test.invalid/" };
globalThis.navigator ??= { userAgent: "node" };
globalThis.fetch = async () => { throw new TypeError("no server in tests"); };
for (const file of ["static/noble.js", "static/e2e.js"]) {
  vm.runInThisContext(readFileSync(join(crate, file), "utf8"), { filename: file });
}
const E = globalThis.HalluE2E;
const { parseKey, deriveKey, seal, open, packPlaintext, unpackPlaintext, hex, REQUEST, RESPONSE } = E._internal;
await E.ready;

const unhex = (s) => Uint8Array.from(s.match(/../g) ?? [], (x) => parseInt(x, 16));
const utf8 = new TextEncoder();

let checks = 0;
for (const backend of ["subtle", "noble"]) {
  const keys = new Map();
  for (const k of vectors.keys) {
    const master = parseKey(k.key);
    assert.equal(hex(master), k.master);
    const key = await deriveKey(master, backend);
    assert.equal(hex(key.kid), k.kid, `${backend}: kid`);
    if (backend === "noble") assert.equal(hex(key.enc), k.enc, "noble: enc");
    keys.set(k.kid, key);
    checks++;
  }
  for (const r of vectors.requests) {
    const key = keys.get(r.kid);
    const plain = packPlaintext(JSON.parse(r.meta_json), unhex(r.body));
    // JSON.stringify keeps the vector's key order and spacing.
    assert.equal(hex(plain), r.plaintext, `${backend}: ${r.name} plaintext`);
    const env = await seal(key, REQUEST, plain, { tsMs: r.ts_ms, nonce: unhex(r.nonce) });
    assert.equal(hex(env), r.envelope, `${backend}: ${r.name} envelope`);
    checks++;
  }
  for (const r of vectors.responses) {
    const key = keys.get(r.kid);
    const opened = await open(key, unhex(r.envelope), RESPONSE, unhex(r.request_nonce));
    assert.equal(hex(opened.plaintext), r.plaintext, `${backend}: ${r.name}`);
    assert.equal(opened.tsMs, r.ts_ms);
    const { meta, body } = unpackPlaintext(opened.plaintext);
    assert.deepEqual(meta, JSON.parse(r.meta_json));
    assert.equal(hex(body), r.body);
    // The request's nonce is in the AAD: without it the reply does not open.
    await assert.rejects(open(key, unhex(r.envelope), RESPONSE, new Uint8Array()), { code: "bad_reply" });
    // A reply sealed here opens again.
    const env = await seal(key, RESPONSE, opened.plaintext, { tsMs: r.ts_ms, nonce: unhex(r.nonce), requestNonce: unhex(r.request_nonce) });
    assert.equal(hex(env), r.envelope, `${backend}: ${r.name} seal`);
    checks++;
  }
}
for (const bad of vectors.bad_keys) {
  assert.throws(() => parseKey(bad), E.BadKey, bad);
  checks++;
}
// The inner request keeps only the headers the server takes, with lowercase names.
const inner = unpackPlaintext(E._internal.innerPlaintext({ method: "get", path: "/api/x", headers: { Authorization: "Bearer t", "X-CSRF-Token": "c" } }));
assert.deepEqual(inner.meta, { m: "GET", p: "/api/x", h: { authorization: "Bearer t" } });
assert.equal(utf8.encode("").length, inner.body.length);
console.log(`e2e-web: ${checks + 1} checks passed (subtle and noble)`);
