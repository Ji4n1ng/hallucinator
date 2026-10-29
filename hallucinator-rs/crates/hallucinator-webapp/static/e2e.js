// hallucinator-webapp — end-to-end encryption in the browser. A plain-JS
// port of Catelier's web client (web/src/lib/e2e.ts: envelopes; tunnel.ts:
// one request through POST /api/e2e; e2eStore.ts: the key per origin in
// IndexedDB; secure.ts: plain or tunnel mode). The wire format is in
// src/e2e.rs. Sets `window.HalluE2E`; app.js and login.js send every API
// request through `HalluE2E.fetch`.
//
// With no key on the server (`/api/health` says `e2e.required: false`)
// requests go plain, as before. Once the server needs a key, every request
// goes sealed, signed in by the session cookie that travels inside the
// envelope, and this browser stays in tunnel mode until the person forgets
// the key. It never falls back to plain.
//
// Two backends give the same bytes:
// - `subtle`: WebCrypto, in a secure context (https, http://localhost). The
//   key is kept as non-extractable CryptoKeys.
// - `noble`: the vendored noble.js, for plain http on a LAN address, where
//   crypto.subtle does not exist. The key is raw bytes that any script on
//   this origin can read.
"use strict";

(function () {
  const PREFIX = "cek1_";
  const VERSION = 1;
  const REQUEST = 1;
  const RESPONSE = 2;
  const HEADER = 30; // version, direction, kid, time, nonce
  const TAG = 16;
  const CONTENT_TYPE = "application/vnd.catelier.e2e";
  const TUNNEL = "/api/e2e";
  /** The only inner headers the server takes from an envelope. */
  const INNER = ["authorization", "content-type", "accept", "user-agent", "cookie", "accept-encoding"];
  const SESSION_COOKIE = "hallu_session";

  class BadKey extends Error {}

  /** An envelope that was refused: by the server (its `e2e` code) or here. */
  class E2EError extends Error {
    constructor(code, detail) {
      super(detail);
      this.code = code;
    }
  }

  const utf8 = new TextEncoder();
  const fromUtf8 = new TextDecoder();

  const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

  function fromBase64(text) {
    const s = text.trim().replace(/-/g, "+").replace(/_/g, "/");
    return Uint8Array.from(atob(s + "=".repeat((4 - (s.length % 4)) % 4)), (c) => c.charCodeAt(0));
  }

  function concat(...parts) {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let at = 0;
    for (const p of parts) {
      out.set(p, at);
      at += p.length;
    }
    return out;
  }

  const randomBytes = (n) => crypto.getRandomValues(new Uint8Array(n));

  /** The backend this context can use. `crypto.getRandomValues` works in both. */
  const pickBackend = () => (globalThis.crypto && crypto.subtle ? "subtle" : "noble");

  function noble() {
    if (!window.HalluNoble) throw new E2EError("bad_reply", "The cipher code (noble.js) did not load.");
    return window.HalluNoble;
  }

  /** The 32 bytes of a `cek1_` key. Throws BadKey with a message for the person who typed it. */
  function parseKey(value) {
    const text = String(value || "").trim();
    if (!text.startsWith(PREFIX)) throw new BadKey(`The key must start with ${PREFIX}`);
    const body = text.slice(PREFIX.length);
    if (body.length !== 43 || !/^[A-Za-z0-9_-]+$/.test(body)) throw new BadKey(`The key must be ${PREFIX} and 43 more characters`);
    const raw = fromBase64(body);
    if (raw.length !== 32) throw new BadKey("The key does not hold 32 bytes");
    return raw;
  }

  // ─── backends ──────────────────────────────────────────────────────────

  async function derive(backend, base, info, length) {
    if (backend === "noble") {
      const n = noble();
      return n.hkdf(n.sha256, base, new Uint8Array(), utf8.encode(info), length);
    }
    const bits = await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(), info: utf8.encode(info) }, base, length * 8);
    return new Uint8Array(bits);
  }

  async function aesKey(backend, raw) {
    if (backend === "noble") return raw;
    return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
  }

  async function gcmSeal(backend, key, nonce, plain, aad) {
    if (backend === "noble") return noble().gcm(key, nonce, aad).encrypt(plain);
    return new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 }, key, plain));
  }

  /** The plaintext, or null when the tag does not match. */
  async function gcmOpen(backend, key, nonce, sealed, aad) {
    try {
      if (backend === "noble") return noble().gcm(key, nonce, aad).decrypt(sealed);
      return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 }, key, sealed));
    } catch (_) {
      return null;
    }
  }

  /**
   * The parts of the key this client keeps: the backend, the key id and the
   * AES key for envelopes. Never the typed `cek1_` string. (No WebSocket
   * here, so the HKDF base is not kept either.)
   */
  async function deriveKey(master, backend) {
    backend = backend || pickBackend();
    const base = backend === "noble" ? master : await crypto.subtle.importKey("raw", master, "HKDF", false, ["deriveBits"]);
    const [enc, kid] = await Promise.all([derive(backend, base, "catelier e2e v1 enc", 32), derive(backend, base, "catelier e2e v1 kid", 8)]);
    return { backend, kid, enc: await aesKey(backend, enc) };
  }

  // ─── envelopes ─────────────────────────────────────────────────────────

  /** uint32 BE length of the meta JSON, the meta JSON, the body. */
  function packPlaintext(meta, body) {
    const raw = utf8.encode(JSON.stringify(meta));
    const head = new Uint8Array(4);
    new DataView(head.buffer).setUint32(0, raw.length);
    return concat(head, raw, body || new Uint8Array());
  }

  function unpackPlaintext(plain) {
    if (plain.length < 4) throw new E2EError("bad_reply", "The reply is too short");
    const n = new DataView(plain.buffer, plain.byteOffset).getUint32(0);
    if (4 + n > plain.length) throw new E2EError("bad_reply", "The reply's meta is cut short");
    let meta;
    try {
      meta = JSON.parse(fromUtf8.decode(plain.subarray(4, 4 + n)));
    } catch (_) {
      throw new E2EError("bad_reply", "The reply's meta is not JSON");
    }
    return { meta, body: plain.slice(4 + n) };
  }

  function header(key, direction, tsMs, nonce) {
    const h = new Uint8Array(HEADER);
    h[0] = VERSION;
    h[1] = direction;
    h.set(key.kid, 2);
    new DataView(h.buffer).setBigUint64(10, BigInt(tsMs));
    h.set(nonce, 18);
    return h;
  }

  /** version | direction | kid | Unix ms | nonce | ciphertext and tag. A response's AAD also holds the request's nonce. */
  async function seal(key, direction, plaintext, opts) {
    opts = opts || {};
    const nonce = opts.nonce || randomBytes(12);
    const head = header(key, direction, opts.tsMs == null ? Date.now() : opts.tsMs, nonce);
    return concat(head, await gcmSeal(key.backend, key.enc, nonce, plaintext, concat(head, opts.requestNonce || new Uint8Array())));
  }

  /** Checks the version, direction and kid, then decrypts. Throws E2EError `bad_reply`. */
  async function open(key, envelope, direction, requestNonce) {
    if (envelope.length < HEADER + TAG) throw new E2EError("bad_reply", "The reply is too short");
    if (envelope[0] !== VERSION || envelope[1] !== direction) throw new E2EError("bad_reply", "Unknown envelope version or direction");
    if (hex(envelope.subarray(2, 10)) !== hex(key.kid)) throw new E2EError("bad_reply", "The reply uses another key");
    const head = envelope.slice(0, HEADER);
    const nonce = envelope.slice(18, 30);
    const plaintext = await gcmOpen(key.backend, key.enc, nonce, envelope.slice(HEADER), concat(head, requestNonce || new Uint8Array()));
    if (!plaintext) throw new E2EError("bad_reply", "The reply could not be decrypted");
    return { tsMs: Number(new DataView(head.buffer).getBigUint64(10)), nonce, plaintext };
  }

  // ─── the key store (IndexedDB, per origin) ─────────────────────────────

  const DB = "hallucinator-e2e";
  const STORE = "keys";
  const memory = new Map(); // when IndexedDB is not available (some private windows)

  function idb() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB, 1);
      req.onupgradeneeded = () => req.result.createObjectStore(STORE, { keyPath: "origin" });
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  async function run(mode, fn) {
    const conn = await idb();
    try {
      return await new Promise((resolve, reject) => {
        const tx = conn.transaction(STORE, mode);
        const req = fn(tx.objectStore(STORE));
        tx.oncomplete = () => resolve(req.result);
        tx.onerror = tx.onabort = () => reject(tx.error || req.error);
      });
    } finally {
      conn.close();
    }
  }

  async function getEntry(origin) {
    try {
      return (await run("readonly", (s) => s.get(origin))) || null;
    } catch (_) {
      return memory.get(origin) || null;
    }
  }

  async function putEntry(entry) {
    memory.set(entry.origin, entry);
    try {
      await run("readwrite", (s) => s.put(entry));
    } catch (_) {
      /* kept in memory for this page only */
    }
  }

  async function deleteEntry(origin) {
    memory.delete(origin);
    try {
      await run("readwrite", (s) => s.delete(origin));
    } catch (_) {
      /* nothing stored */
    }
  }

  // ─── one request through the tunnel ────────────────────────────────────

  /** The inner meta and body as the server expects them: `{m, p, h}`, lowercase header names. */
  function innerPlaintext(req) {
    const h = {};
    for (const [name, value] of Object.entries(req.headers || {})) {
      const n = name.toLowerCase();
      if (value != null && INNER.includes(n)) h[n] = String(value);
    }
    const body = typeof req.body === "string" ? utf8.encode(req.body) : req.body || new Uint8Array();
    return packPlaintext({ m: req.method.toUpperCase(), p: req.path, h }, body);
  }

  /** A gzip body inflated: the server compresses big replies before it seals them. */
  async function gunzip(body) {
    const stream = new Blob([body]).stream().pipeThrough(new DecompressionStream("gzip"));
    return new Uint8Array(await new Response(stream).arrayBuffer());
  }

  /** POST the envelope. With `onUploadProgress`, by XMLHttpRequest, which reports upload progress. */
  function post(sealed, onUploadProgress) {
    if (!onUploadProgress) {
      // No cookies: an old plain-mode session cookie must not travel next to the envelope.
      return fetch(TUNNEL, { method: "POST", credentials: "omit", cache: "no-store", headers: { "Content-Type": CONTENT_TYPE }, body: sealed })
        .then(async (res) => ({ status: res.status, type: res.headers.get("content-type"), body: new Uint8Array(await res.arrayBuffer()) }));
    }
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open("POST", TUNNEL);
      xhr.responseType = "arraybuffer";
      xhr.setRequestHeader("Content-Type", CONTENT_TYPE);
      xhr.upload.onprogress = onUploadProgress;
      xhr.onload = () => resolve({ status: xhr.status, type: xhr.getResponseHeader("content-type"), body: new Uint8Array(xhr.response || new ArrayBuffer(0)) });
      xhr.onerror = () => reject(new TypeError("Network error"));
      xhr.send(sealed);
    });
  }

  /** An envelope error the server answers in plain JSON (HTTP 400 `{detail, e2e}`), or another outer failure. */
  function refusal(res) {
    try {
      const data = JSON.parse(fromUtf8.decode(res.body));
      if (data && typeof data.e2e === "string") return new E2EError(data.e2e, String(data.detail || data.e2e));
      if (res.status === 413) return new E2EError("too_large", String((data && data.detail) || "The request is too large"));
    } catch (_) {
      /* not JSON */
    }
    return new E2EError("off", `The server did not take the encrypted request (HTTP ${res.status})`);
  }

  async function tunnelRequest(key, req, onUploadProgress) {
    const headers = Object.assign({}, req.headers);
    if (typeof DecompressionStream === "function" && !Object.keys(headers).some((k) => k.toLowerCase() === "accept-encoding")) headers["accept-encoding"] = "gzip";
    const sealed = await seal(key, REQUEST, innerPlaintext(Object.assign({}, req, { headers })));
    const nonce = sealed.slice(18, 30);
    const res = await post(sealed, onUploadProgress);
    if (res.status !== 200 || res.type !== CONTENT_TYPE) throw refusal(res);
    const opened = await open(key, res.body, RESPONSE, nonce);
    const { meta, body } = unpackPlaintext(opened.plaintext);
    if (typeof meta.s !== "number") throw new E2EError("bad_reply", "The reply has no status");
    const h = Object.assign({}, meta.h || {});
    let out = body;
    if (h["content-encoding"] === "gzip") {
      out = await gunzip(body);
      delete h["content-encoding"];
      delete h["content-length"];
    }
    return { status: meta.s, headers: h, body: out, rotate: meta.rotate === true };
  }

  const NULL_BODY = [101, 103, 204, 205, 304];

  /** A fetch Response made from a tunnel reply, so callers read it as they read a plain one. */
  function toResponse(reply) {
    const headers = new Headers();
    for (const [name, value] of Object.entries(reply.headers)) {
      if (name === "set-cookie") continue; // a Response can't carry it; secureFetch keeps the session
      if (typeof value === "string") headers.set(name, value);
    }
    const status = reply.status >= 200 && reply.status <= 599 ? reply.status : 502;
    return new Response(NULL_BODY.includes(status) ? null : reply.body, { status, headers });
  }

  // ─── plain or tunnel mode ──────────────────────────────────────────────

  const MESSAGES = {
    required: "This server requires an encryption key.",
    no_key: "This server requires an encryption key.",
    unknown_kid: "This key does not match the server's key.",
    bad_envelope: "The server could not decrypt the request. Check the encryption key.",
    stale: "The clock on this device is off by more than 2 minutes.",
    replay: "The server received the same request twice. Try again.",
    blocked: "Too many requests from this address could not be decrypted. Wait, then try again.",
    bad_reply: "The server's reply could not be decrypted. Check the encryption key.",
    off: "The server did not take the encrypted request. If the server no longer uses a key, forget the key on this device.",
  };

  const message = (code, detail) => MESSAGES[code] || detail || "The encrypted connection failed.";

  const origin = location.origin;
  let entry = null; // {origin, key?, session?}
  const state = { ready: false, mode: "plain", hasKey: false, kid: null, backend: pickBackend(), error: null, rotate: false };

  function fromEntry() {
    state.mode = entry ? "tunnel" : "plain";
    state.hasKey = !!(entry && entry.key);
    state.kid = entry && entry.key ? hex(entry.key.kid) : null;
  }

  const save = () => (entry ? putEntry(entry).catch(() => {}) : Promise.resolve());

  async function health() {
    try {
      const res = await fetch("/api/health", { credentials: "omit", cache: "no-store" });
      const data = await res.json();
      const e2e = (data && data.e2e) || {};
      return { required: e2e.required === true, kids: Array.isArray(e2e.kids) ? e2e.kids : [] };
    } catch (_) {
      return null; // server down: keep what is stored
    }
  }

  // Whether /api/health has answered. Until it has, nothing goes plain: a
  // sign-in must not send a password plain to a server that needs a key.
  let healthKnown = false;

  async function learnMode() {
    const h = await health();
    if (!h) return false;
    healthKnown = true;
    if (h.required && !entry) {
      entry = { origin };
      await save();
    }
    fromEntry();
    return true;
  }

  const ready = (async () => {
    entry = await getEntry(origin);
    await learnMode();
    fromEntry();
    state.ready = true;
  })();

  function fail(code, detail) {
    state.error = { code, message: message(code, detail) };
    return new E2EError(code, message(code, detail));
  }

  /** Keep the session cookie the server sets (or clears) inside a sealed reply. */
  function keepSession(setCookie) {
    const list = typeof setCookie === "string" ? [setCookie] : setCookie || [];
    let changed = false;
    for (const c of list) {
      const m = new RegExp(`^${SESSION_COOKIE}=([^;]*)`).exec(c);
      if (!m) continue;
      const gone = !m[1] || /;\s*max-age=0\b/i.test(c);
      entry.session = gone ? undefined : m[1];
      changed = true;
    }
    return changed;
  }

  /** A plain XMLHttpRequest that reports upload progress, as a Response. */
  function xhrFetch(path, method, headers, body, onUploadProgress) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open(method, path);
      xhr.responseType = "arraybuffer";
      for (const [k, v] of Object.entries(headers || {})) xhr.setRequestHeader(k, v);
      xhr.upload.onprogress = onUploadProgress;
      xhr.onload = () => {
        const h = new Headers();
        for (const line of xhr.getAllResponseHeaders().trim().split(/[\r\n]+/)) {
          const i = line.indexOf(":");
          if (i > 0) {
            try { h.append(line.slice(0, i).trim(), line.slice(i + 1).trim()); } catch (_) { /* skip */ }
          }
        }
        resolve(new Response(NULL_BODY.includes(xhr.status) ? null : xhr.response, { status: xhr.status, headers: h }));
      };
      xhr.onerror = () => reject(new TypeError("Network error"));
      xhr.send(body);
    });
  }

  /**
   * `fetch` for the server's `/api/` routes, plain or through the tunnel as
   * the server needs. init: {method, headers, body (string, bytes or
   * FormData), onUploadProgress}. Throws E2EError when the envelope fails.
   */
  async function secureFetch(path, init) {
    init = init || {};
    await ready;
    const method = (init.method || "GET").toUpperCase();
    if (state.mode === "plain" && !healthKnown && !(await learnMode())) {
      throw new TypeError("The server can't be reached.");
    }
    if (state.mode === "plain") {
      const res = init.onUploadProgress
        ? await xhrFetch(path, method, init.headers, init.body, init.onUploadProgress)
        : await fetch(path, { method, credentials: "same-origin", headers: init.headers, body: init.body });
      if (res.status === 400) {
        const data = await res.clone().json().catch(() => null);
        if (data && data.e2e === "required") {
          // The server has a key now: from here on, never plain.
          entry = { origin };
          await save();
          fromEntry();
          throw fail("required");
        }
      }
      return res;
    }
    const key = entry && entry.key;
    if (!key) throw fail("no_key");
    const headers = { "user-agent": navigator.userAgent };
    for (const [k, v] of Object.entries(init.headers || {})) headers[k.toLowerCase()] = v;
    if (entry.session) headers.cookie = `${SESSION_COOKIE}=${entry.session}`;
    let body = init.body;
    if (body instanceof FormData) {
      const r = new Response(body);
      headers["content-type"] = r.headers.get("content-type");
      body = new Uint8Array(await r.arrayBuffer());
    }
    let reply;
    try {
      reply = await tunnelRequest(key, { method, path, headers, body }, init.onUploadProgress);
    } catch (e) {
      if (!(e instanceof E2EError)) throw e; // offline: as a plain fetch would fail
      if (e.code === "too_large") return new Response(JSON.stringify({ error: e.message }), { status: 413, headers: { "content-type": "application/json" } });
      throw fail(e.code, e.message);
    }
    let changed = keepSession(reply.headers["set-cookie"]);
    if (reply.status === 401 && entry.session && !path.startsWith("/api/auth/login")) {
      entry.session = undefined; // the session ended on the server
      changed = true;
    }
    if (changed) await save();
    if (reply.status < 500) state.rotate = reply.rotate;
    return toResponse(reply);
  }

  /** Checks a typed key against the server's key ids (no request is sealed with it), then stores it. */
  async function enterKey(text) {
    const master = parseKey(text);
    const h = await health();
    if (!h) throw new Error("The server can't be reached. Try again.");
    const key = await deriveKey(master, pickBackend());
    if (!h.kids.includes(hex(key.kid))) throw new BadKey(MESSAGES.unknown_kid);
    entry = Object.assign({}, entry || { origin }, { key });
    await save();
    fromEntry();
    state.error = null;
    state.rotate = h.kids[0] !== hex(key.kid);
  }

  /** Deletes the key and the session kept with it. The server decides the mode again on the next load. */
  async function forgetKey() {
    if (entry && entry.key && entry.session) await secureFetch("/api/auth/logout", { method: "POST" }).catch(() => {});
    await deleteEntry(origin);
    entry = null;
    fromEntry();
  }

  /** The key step must come first: tunnel mode without a key, or the last envelope failed. */
  const needsKey = () => state.ready && state.mode === "tunnel" && (!state.hasKey || !!state.error);

  function filename(disposition, fallback) {
    const star = /filename\*=UTF-8''([^;]+)/i.exec(disposition || "");
    if (star) return decodeURIComponent(star[1]);
    const m = /filename="?([^";]+)"?/i.exec(disposition || "");
    return m ? m[1] : fallback;
  }

  /** Saves a file from the server (fetched sealed in tunnel mode), with the name the server gives it. */
  async function download(path) {
    const res = await secureFetch(path);
    if (!res.ok) {
      const d = await res.json().catch(() => null);
      throw new Error((d && (d.error || d.detail)) || `Download failed (HTTP ${res.status})`);
    }
    const url = URL.createObjectURL(await res.blob());
    const a = document.createElement("a");
    a.href = url;
    a.download = filename(res.headers.get("content-disposition"), path.split("?")[0].split("/").pop() || "download");
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  }

  /** Opens a text document from the server (e.g. the API guide) in a new tab. */
  async function openText(path) {
    const win = window.open("", "_blank"); // now, while the click still counts
    try {
      const res = await secureFetch(path);
      const text = await res.text();
      const url = URL.createObjectURL(new Blob([text], { type: "text/plain; charset=utf-8" }));
      if (win) win.location.href = url;
      else location.href = url;
      setTimeout(() => URL.revokeObjectURL(url), 60000);
    } catch (e) {
      if (win) win.close();
      throw e;
    }
  }

  window.HalluE2E = {
    ready,
    state,
    fetch: secureFetch,
    tunnel: () => state.mode === "tunnel",
    needsKey,
    enterKey,
    forgetKey,
    retry: () => { state.error = null; },
    message,
    download,
    openText,
    E2EError,
    BadKey,
    // For tests (static/e2e.test.mjs) and debugging; no secrets.
    _internal: { parseKey, deriveKey, seal, open, packPlaintext, unpackPlaintext, innerPlaintext, hex, REQUEST, RESPONSE },
  };
})();
