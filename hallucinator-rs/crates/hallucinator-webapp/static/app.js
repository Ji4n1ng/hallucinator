// hallucinator-webapp — single-page browser client.
//
// Contract with the server: API.md (same crate). No framework, no build step.
// All DOM is built with `h()` + textContent, never innerHTML with server data.
//
// Sections:
//   1. Utilities (DOM, formatting, links)
//   2. API client (CSRF, 401 redirect, errors)
//   3. UI primitives (toasts, modals, dropdowns, badges)
//   4. Shell (nav, user menu) + router
//   5. Views: new check · run · history · databases · admin · account
"use strict";

(function () {
  // ════════════════════════════════════════════════════════════════════
  // 1. Utilities
  // ════════════════════════════════════════════════════════════════════

  const BOOL_PROPS = new Set(["checked", "disabled", "selected", "hidden", "multiple", "required", "readOnly", "open"]);

  /** Create an element. attrs: class, dataset, style (object), on<Event> (fn), props, plain attrs. */
  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (v == null || v === false) continue;
        if (k === "class") el.className = v;
        else if (k === "dataset") Object.assign(el.dataset, v);
        else if (k === "style" && typeof v === "object") Object.assign(el.style, v);
        else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2).toLowerCase(), v);
        else if (k === "value") el.value = v;
        else if (BOOL_PROPS.has(k)) el[k] = !!v;
        else if (k === "text") el.textContent = v;
        else if (v === true) el.setAttribute(k, "");
        else el.setAttribute(k, String(v));
      }
    }
    append(el, children);
    return el;
  }

  function append(el, ...children) {
    for (const c of children.flat(Infinity)) {
      if (c == null || c === false || c === "") continue;
      el.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return el;
  }

  function clear(el) {
    while (el.firstChild) el.removeChild(el.firstChild);
    return el;
  }

  function replace(el, ...children) {
    clear(el);
    return append(el, children);
  }

  const $ = (sel, root) => (root || document).querySelector(sel);

  function debounce(fn, ms) {
    let t = null;
    return (...args) => {
      clearTimeout(t);
      t = setTimeout(() => fn(...args), ms);
    };
  }

  const nowSec = () => Math.floor(Date.now() / 1000);

  function fmtNum(n) {
    if (n == null || !Number.isFinite(Number(n))) return "—";
    return Number(n).toLocaleString();
  }

  function fmtBytes(b) {
    if (b == null || !Number.isFinite(b)) return "—";
    const units = ["B", "KB", "MB", "GB", "TB"];
    let i = 0;
    let v = b;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
  }

  function absTime(ts) {
    if (!ts) return "";
    return new Date(ts * 1000).toLocaleString();
  }

  function relTime(ts) {
    if (!ts) return "—";
    const d = nowSec() - ts;
    if (d < 0) {
      const f = -d;
      if (f < 60) return "in a few seconds";
      if (f < 3600) return `in ${Math.round(f / 60)} min`;
      if (f < 86400) return `in ${Math.round(f / 3600)} h`;
      return `in ${Math.round(f / 86400)} days`;
    }
    if (d < 45) return "just now";
    if (d < 3600) return `${Math.max(1, Math.round(d / 60))} min ago`;
    if (d < 86400) return `${Math.round(d / 3600)} h ago`;
    if (d < 86400 * 7) {
      const days = Math.round(d / 86400);
      return days === 1 ? "yesterday" : `${days} days ago`;
    }
    return new Date(ts * 1000).toLocaleDateString();
  }

  /** <time> element with relative text and absolute tooltip. */
  function timeEl(ts) {
    if (!ts) return h("span", { class: "stone" }, "—");
    return h("time", { datetime: new Date(ts * 1000).toISOString(), title: absTime(ts) }, relTime(ts));
  }

  function fmtDuration(secs) {
    if (secs == null || secs < 0) return "—";
    if (secs < 60) return `${secs}s`;
    const m = Math.floor(secs / 60);
    if (m < 60) return `${m}m ${secs % 60}s`;
    const hrs = Math.floor(m / 60);
    return `${hrs}h ${m % 60}m`;
  }

  function fmtDate(s) {
    if (!s) return "—";
    // Some offline DBs record their build time as unix seconds.
    if (/^\d{9,11}$/.test(String(s).trim())) return new Date(Number(s) * 1000).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
    const t = Date.parse(s);
    if (Number.isFinite(t)) return new Date(t).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
    return String(s);
  }

  function plural(n, one, many) {
    return `${fmtNum(n)} ${n === 1 ? one : (many || one + "s")}`;
  }

  /** A file name with line-break opportunities after "_" and "-", so long names wrap between words. */
  function breakableName(name) {
    const parts = String(name || "").match(/[^_-]+[_-]*|[_-]+/g) || [];
    return parts.flatMap((part, i) => (i ? [h("wbr"), part] : [part]));
  }

  function isHttpUrl(u) {
    return typeof u === "string" && /^https?:\/\//i.test(u.trim());
  }

  /** External link; falls back to plain text for anything that isn't http(s). */
  function extLink(url, text) {
    const label = text == null ? url : text;
    if (!isHttpUrl(url)) return h("span", { class: "break" }, label);
    return h("a", { href: url.trim(), target: "_blank", rel: "noopener noreferrer", class: "break" }, label);
  }

  const doiUrl = (doi) => "https://doi.org/" + encodeURI(String(doi).trim());
  const arxivUrl = (id) => "https://arxiv.org/abs/" + encodeURI(String(id).trim());

  function fileStem(name) {
    const lower = name.toLowerCase();
    for (const ext of [".tar.gz", ".tgz", ".pdf", ".bib", ".bbl", ".xml", ".zip"]) {
      if (lower.endsWith(ext)) return name.slice(0, name.length - ext.length);
    }
    const i = name.lastIndexOf(".");
    return i > 0 ? name.slice(0, i) : name;
  }

  function fileExt(name) {
    const lower = name.toLowerCase();
    if (lower.endsWith(".tar.gz")) return "tar.gz";
    if (lower.endsWith(".tgz")) return "tgz";
    const i = lower.lastIndexOf(".");
    return i >= 0 ? lower.slice(i + 1) : "";
  }

  function isTypingTarget(el) {
    if (!el) return false;
    const tag = el.tagName;
    return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || el.isContentEditable;
  }

  const isNarrow = () => window.matchMedia("(max-width: 1023px)").matches;

  // ════════════════════════════════════════════════════════════════════
  // 2. API client
  // ════════════════════════════════════════════════════════════════════

  const S = {
    user: null,
    csrf: null,
    options: null, // cached /api/options
  };

  class ApiError extends Error {
    constructor(status, message, data, retryAfter) {
      super(message);
      this.status = status;
      this.data = data;
      this.retryAfter = retryAfter || 0;
    }
  }

  function toLogin(expired) {
    location.href = expired ? "/login?expired=1" : "/login";
  }

  async function api(method, path, body) {
    const headers = { Accept: "application/json" };
    if (method !== "GET" && method !== "HEAD") headers["X-CSRF-Token"] = S.csrf || "";
    let payload;
    if (body instanceof FormData) payload = body;
    else if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      payload = JSON.stringify(body);
    }
    let res;
    try {
      res = await fetch(path, { method, headers, body: payload, credentials: "same-origin" });
    } catch (_) {
      throw new ApiError(0, "Network error — could not reach the server.");
    }
    if (res.status === 401) {
      toLogin(!!S.user);
      throw new ApiError(401, "Not signed in.");
    }
    if (res.status === 204) return null;
    let data = null;
    const ct = res.headers.get("content-type") || "";
    if (ct.includes("application/json")) {
      try { data = await res.json(); } catch (_) { data = null; }
    }
    if (!res.ok) {
      let ra = data && Number.isFinite(data.retry_after) ? data.retry_after : parseInt(res.headers.get("Retry-After") || "0", 10);
      if (!Number.isFinite(ra)) ra = 0;
      const msg = (data && data.error) || `Request failed (HTTP ${res.status}).`;
      throw new ApiError(res.status, msg, data, ra);
    }
    return data;
  }

  function showError(e) {
    if (e && e.status === 401) return;
    toast((e && e.message) || String(e), "error");
  }

  async function loadOptions() {
    if (!S.options) S.options = await api("GET", "/api/options");
    return S.options;
  }

  // ════════════════════════════════════════════════════════════════════
  // 3. UI primitives
  // ════════════════════════════════════════════════════════════════════

  function toast(message, kind, timeout) {
    const box = $("#toasts");
    const t = h("div", { class: "toast" + (kind ? " " + kind : ""), role: kind === "error" ? "alert" : "status" },
      h("span", { class: "grow break" }, message),
      h("button", { class: "t-close", type: "button", "aria-label": "Dismiss", onclick: () => t.remove() }, "×"));
    box.appendChild(t);
    const ms = timeout != null ? timeout : (kind === "error" ? 8000 : 4000);
    if (ms > 0) setTimeout(() => t.remove(), ms);
    return t;
  }

  const overlayStack = [];

  function focusables(root) {
    return Array.from(root.querySelectorAll("a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex='-1'])"))
      .filter((el) => el.offsetParent !== null || el === document.activeElement);
  }

  /** Generic modal. Returns { el, body, close }. */
  function openModal({ title, body, actions, wide, onClose, label }) {
    const prevFocus = document.activeElement;
    const titleId = "m-" + Math.random().toString(36).slice(2);
    const modal = h("div", { class: "modal" + (wide ? " wide" : ""), role: "dialog", "aria-modal": "true", "aria-labelledby": title ? titleId : null, "aria-label": title ? null : (label || "Dialog") });
    const backdrop = h("div", { class: "modal-backdrop" }, modal);
    let closed = false;
    const entry = {
      el: modal,
      close() {
        if (closed) return;
        closed = true;
        backdrop.remove();
        const i = overlayStack.indexOf(entry);
        if (i >= 0) overlayStack.splice(i, 1);
        if (onClose) onClose();
        if (prevFocus && prevFocus.focus && document.contains(prevFocus)) prevFocus.focus();
      },
    };
    if (title) modal.appendChild(h("div", { class: "row-between" }, h("h2", { id: titleId }, title),
      h("button", { type: "button", class: "btn-icon", "aria-label": "Close", onclick: () => entry.close() }, "×")));
    const bodyEl = h("div", { class: "stack" });
    if (body) append(bodyEl, [body]);
    modal.appendChild(bodyEl);
    entry.body = bodyEl;
    if (actions && actions.length) modal.appendChild(h("div", { class: "modal-actions" }, actions));
    backdrop.addEventListener("mousedown", (e) => { if (e.target === backdrop) entry.close(); });
    modal.addEventListener("keydown", (e) => {
      if (e.key === "Escape") { e.stopPropagation(); entry.close(); }
      if (e.key === "Tab") {
        const f = focusables(modal);
        if (!f.length) return;
        const first = f[0];
        const last = f[f.length - 1];
        if (e.shiftKey && document.activeElement === first) { last.focus(); e.preventDefault(); }
        else if (!e.shiftKey && document.activeElement === last) { first.focus(); e.preventDefault(); }
      }
    });
    $("#overlay-root").appendChild(backdrop);
    overlayStack.push(entry);
    const f = focusables(modal);
    const target = f.find((el) => el.matches("input, select, textarea")) || f.find((el) => !el.classList.contains("btn-icon")) || f[0];
    if (target) setTimeout(() => target.focus(), 0);
    return entry;
  }

  function confirmDialog({ title, message, confirmLabel, danger }) {
    return new Promise((resolve) => {
      let result = false;
      const ok = h("button", { type: "button", class: "btn " + (danger ? "btn-danger" : "btn-primary"), onclick: () => { result = true; m.close(); } }, confirmLabel || "Confirm");
      const cancel = h("button", { type: "button", class: "btn btn-tertiary", onclick: () => m.close() }, "Cancel");
      const m = openModal({
        title,
        body: typeof message === "string" ? h("p", { class: "muted" }, message) : message,
        actions: [cancel, ok],
        onClose: () => resolve(result),
      });
      setTimeout(() => ok.focus(), 0);
    });
  }

  function closeAllOverlays() {
    while (overlayStack.length) overlayStack[overlayStack.length - 1].close();
  }

  /** Dropdown: a trigger button + a floating menu container. Returns { root, menu, close }. */
  function dropdown(triggerLabel, buildMenu, opts) {
    opts = opts || {};
    const menu = h("div", { class: "menu hidden", role: "menu" });
    const trigger = h("button", {
      type: "button",
      class: opts.class || "btn btn-tertiary btn-sm",
      "aria-haspopup": "menu",
      "aria-expanded": "false",
      disabled: !!opts.disabled,
    }, triggerLabel, " ▾");
    const root = h("div", { class: "dropdown" }, trigger, menu);
    const onDoc = (e) => { if (!root.contains(e.target)) close(); };
    const onKey = (e) => { if (e.key === "Escape") { close(); trigger.focus(); } };
    function open() {
      replace(menu, buildMenu(close));
      menu.classList.remove("hidden");
      trigger.setAttribute("aria-expanded", "true");
      document.addEventListener("mousedown", onDoc);
      document.addEventListener("keydown", onKey);
      const first = focusables(menu)[0];
      if (first) first.focus();
    }
    function close() {
      menu.classList.add("hidden");
      trigger.setAttribute("aria-expanded", "false");
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    }
    trigger.addEventListener("click", () => (menu.classList.contains("hidden") ? open() : close()));
    if (opts.alignLeft) menu.style.left = "0";
    if (opts.alignLeft) menu.style.right = "auto";
    return { root, menu, close, trigger };
  }

  function badge(text, cls, title) {
    return h("span", { class: "badge " + (cls || ""), title: title || null }, text);
  }

  function pulseBadge(text, cls) {
    return h("span", { class: "badge " + (cls || "badge-beta") }, h("span", { class: "dot pulse", "aria-hidden": "true" }), text);
  }

  function emptyState(title, text, action) {
    return h("div", { class: "empty" }, h("div", { class: "empty-title" }, title), text ? h("p", null, text) : null, action ? h("div", { class: "mt-md" }, action) : null);
  }

  function skeleton(lines) {
    const out = [h("div", { class: "skel skel-block" })];
    for (let i = 0; i < (lines || 3); i++) out.push(h("div", { class: "skel skel-line", style: { width: `${90 - i * 12}%` } }));
    return h("div", { "aria-hidden": "true" }, out);
  }

  function progressBar(fraction, cls) {
    const pct = Math.max(0, Math.min(1, fraction || 0)) * 100;
    return h("div", { class: "progress " + (cls || ""), role: "progressbar", "aria-valuemin": "0", "aria-valuemax": "100", "aria-valuenow": String(Math.round(pct)) },
      h("div", { class: "bar", style: { width: pct + "%" } }));
  }

  /** Progress over checked + pending references, split by outcome (verified / problem / other). */
  function outcomeBar(st, cls) {
    st = st || {};
    const checked = st.checked || 0;
    const denom = checked + (st.pending || 0);
    const bad = Math.min(st.problems || 0, checked);
    const ok = Math.min(st.verified || 0, checked - bad);
    const other = checked - bad - ok;
    const width = (n) => (denom ? (100 * n) / denom : 0) + "%";
    const label = denom
      ? `${fmtNum(checked)} of ${fmtNum(denom)} checked: ${fmtNum(ok)} verified, ${plural(bad, "problem")}, ${fmtNum(other)} other`
      : "No references checked yet";
    return h("div", {
      class: "progress outcome " + (cls || ""), role: "progressbar", title: label, "aria-label": label,
      "aria-valuemin": "0", "aria-valuemax": "100", "aria-valuenow": String(denom ? Math.round((100 * checked) / denom) : 0),
    },
      h("span", { class: "seg seg-ok", style: { width: width(ok) } }),
      h("span", { class: "seg seg-bad", style: { width: width(bad) } }),
      h("span", { class: "seg seg-other", style: { width: width(other) } }));
  }

  function outcomeLegend() {
    const item = (cls, label) => h("span", { class: "legend-item" }, h("span", { class: "legend-swatch " + cls, "aria-hidden": "true" }), label);
    return h("div", { class: "legend", "aria-hidden": "true" },
      item("seg-ok", "Verified"), item("seg-bad", "Problem"), item("seg-other", "Skipped / inconclusive"), item("seg-pending", "Pending"));
  }

  function switchEl(label, opts) {
    const input = h("input", { type: "checkbox", checked: !!opts.checked, disabled: !!opts.disabled, onchange: opts.onchange || null });
    const el = h("label", { class: "switch" + (opts.disabled ? " disabled" : ""), title: opts.title || null }, input, h("span", { class: "track", "aria-hidden": "true" }), h("span", null, label));
    return { el, input };
  }

  // ── domain constants & badges ───────────────────────────────────────

  const FP_REASONS = [
    { key: "broken_parse", label: "Broken citation parse", short: "parse" },
    { key: "exists_elsewhere", label: "Found on Google Scholar / other source", short: "GS" },
    { key: "all_timed_out", label: "All databases timed out", short: "timeout" },
    { key: "known_good", label: "User verified as real", short: "known" },
    { key: "non_academic", label: "Non-academic source (RFC, legal, news, etc.)", short: "N/A" },
  ];
  const FP_BY_KEY = Object.fromEntries(FP_REASONS.map((r) => [r.key, r]));

  const STAT_KEYS = ["total", "checked", "pending", "verified", "not_found", "mismatch", "author_mismatch", "doi_mismatch", "arxiv_mismatch", "retracted", "skipped", "inconclusive", "marked_safe", "problems"];

  const SKIP_LABELS = {
    url_only: "URL-only reference (no academic title to look up)",
    short_title: "Title too short to match reliably",
    no_title: "No title could be parsed",
  };

  const DB_STATUS_LABELS = {
    match: "Match", no_match: "No match", author_mismatch: "Author mismatch", timeout: "Timeout",
    rate_limited: "Rate limited", error: "Error", skipped: "Skipped",
  };

  const MISMATCH_LABELS = { author: "Author mismatch", doi: "DOI mismatch", arxiv_id: "arXiv ID mismatch" };

  const KIND_LABELS = { pdf: "PDF", bib: "BIB", bbl: "BBL", xml: "GROBID XML", "pdf+bib": "PDF + BIB", "pdf+bbl": "PDF + BBL" };

  function kindBadge(kind) {
    const label = KIND_LABELS[kind] || String(kind || "").toUpperCase();
    return badge(label, kind && kind.includes("+") ? "badge-beta badge-sm" : "badge-outline badge-sm");
  }

  function runStatusBadge(status) {
    switch (status) {
      case "queued": return badge("Queued", "badge-outline");
      case "running": return pulseBadge("Running");
      case "done": return badge("Done", "badge-success");
      case "cancelled": return badge("Cancelled", "badge-muted");
      case "failed": return badge("Failed", "badge-error");
      case "interrupted": return badge("Interrupted", "badge-warn", "The server restarted while this run was in progress");
      default: return badge(status || "—", "badge-muted");
    }
  }

  function paperStatusBadge(status) {
    switch (status) {
      case "queued": return badge("Queued", "badge-outline badge-sm");
      case "extracting": return pulseBadge("Extracting", "badge-beta badge-sm");
      case "checking": return pulseBadge("Checking", "badge-beta badge-sm");
      case "done": return badge("Done", "badge-success badge-sm");
      case "failed": return badge("Failed", "badge-error badge-sm");
      case "cancelled": return badge("Cancelled", "badge-muted badge-sm");
      default: return badge(status || "—", "badge-muted badge-sm");
    }
  }

  function jobStatusBadge(status) {
    switch (status) {
      case "running": return pulseBadge("Running");
      case "succeeded": return badge("Succeeded", "badge-success");
      case "failed": return badge("Failed", "badge-error");
      case "cancelled": return badge("Cancelled", "badge-muted");
      case "interrupted": return badge("Interrupted", "badge-warn");
      default: return badge(status || "—", "badge-muted");
    }
  }

  function isProblem(r) {
    if (r.fp_reason) return false;
    return r.verdict === "not_found" || r.verdict === "mismatch" || !!r.retracted;
  }

  function mismatchLabel(r) {
    const kinds = (r.result && r.result.mismatch) || [];
    if (kinds.length === 1) return MISMATCH_LABELS[kinds[0]] || "Mismatch";
    return "Mismatch";
  }

  function verdictBadges(r) {
    const out = [];
    switch (r.phase) {
      case "pending": out.push(badge("Pending", "v-pending")); break;
      case "checking": out.push(h("span", { class: "badge v-checking" }, h("span", { class: "dot pulse", "aria-hidden": "true" }), "Checking")); break;
      case "retrying": out.push(h("span", { class: "badge v-checking" }, h("span", { class: "dot pulse", "aria-hidden": "true" }), "Retrying")); break;
      case "skipped": out.push(badge("Skipped", "v-skipped", SKIP_LABELS[r.skip_reason] || r.skip_reason || "")); break;
      default: break;
    }
    if (r.phase === "done" || (r.phase === "retrying" && r.verdict)) {
      switch (r.verdict) {
        case "verified": out.push(badge("Verified", "v-verified")); break;
        case "not_found": out.push(badge("Not found", "v-not_found")); break;
        case "mismatch": out.push(badge(mismatchLabel(r), "v-mismatch")); break;
        case "inconclusive": out.push(badge("Inconclusive", "v-inconclusive")); break;
        case "skipped": out.push(badge("Skipped", "v-skipped", "URL check disabled for this run")); break;
        default: break;
      }
    }
    if (r.retracted) out.push(badge("Retracted", "v-retracted"));
    return out;
  }

  function fpBadge(reason) {
    const fp = FP_BY_KEY[reason];
    if (!fp) return null;
    return badge("Safe · " + fp.short, "v-safe", fp.label);
  }

  function severity(r) {
    if (r.fp_reason) return 9;
    if (r.retracted) return 0;
    switch (r.verdict) {
      case "not_found": return 1;
      case "mismatch": return 2;
      case "inconclusive": return 3;
      case "verified": return 7;
      case "skipped": return 8;
      default: break;
    }
    if (r.phase === "checking" || r.phase === "retrying") return 4;
    if (r.phase === "pending") return 5;
    if (r.phase === "skipped") return 8;
    return 6;
  }

  function sumStats(list) {
    const out = Object.fromEntries(STAT_KEYS.map((k) => [k, 0]));
    for (const s of list) {
      if (!s) continue;
      for (const k of STAT_KEYS) out[k] += Number(s[k] || 0);
    }
    return out;
  }

  function statsStrip(st) {
    st = st || {};
    const cell = (num, label, cls) => h("div", { class: "stat " + (cls || "") },
      h("div", { class: "stat-num" }, fmtNum(num || 0)), h("div", { class: "stat-label" }, label));
    return h("div", { class: "stats-strip", role: "group", "aria-label": "Run statistics" },
      cell(st.total, "Total"),
      cell(st.verified, "Verified", "good"),
      cell(st.problems, "Problems", st.problems ? "bad" : ""),
      cell(st.not_found, "Not found", st.not_found ? "bad" : ""),
      cell(st.mismatch, "Mismatch", st.mismatch ? "warn" : ""),
      cell(st.inconclusive, "Inconclusive"),
      cell(st.skipped, "Skipped"),
      cell(st.marked_safe, "Marked safe", st.marked_safe ? "blue" : ""));
  }

  // ════════════════════════════════════════════════════════════════════
  // 4. Shell + router
  // ════════════════════════════════════════════════════════════════════

  let routeToken = 0;
  let currentCtx = null;

  function newCtx() {
    const ctx = {
      token: ++routeToken,
      cleanups: [],
      alive() { return ctx.token === routeToken; },
      on(fn) { ctx.cleanups.push(fn); },
    };
    return ctx;
  }

  const ROUTES = [
    { re: /^\/?$/, nav: "new", view: viewNew },
    { re: /^\/runs\/([A-Za-z0-9_-]+)\/?$/, nav: "history", view: viewRun },
    { re: /^\/history\/?$/, nav: "history", view: viewHistory },
    { re: /^\/databases\/?$/, nav: "databases", view: viewDatabases },
    { re: /^\/admin\/?$/, nav: "admin", view: viewAdmin },
    { re: /^\/account\/?$/, nav: "account", view: viewAccount },
  ];

  function route() {
    if (currentCtx) {
      for (const fn of currentCtx.cleanups) { try { fn(); } catch (_) { /* ignore */ } }
    }
    closeAllOverlays();
    closeMobileNav();
    closeUserMenu();
    const ctx = newCtx();
    currentCtx = ctx;
    const hash = (location.hash || "#/").replace(/^#/, "");
    const path = hash.split("?")[0] || "/";
    const root = $("#app");
    clear(root);
    root.setAttribute("aria-busy", "true");
    let matched = null;
    let m = null;
    for (const r of ROUTES) {
      m = path.match(r.re);
      if (m) { matched = r; break; }
    }
    document.querySelectorAll(".navlink").forEach((a) => {
      if (matched && a.dataset.route === matched.nav) a.setAttribute("aria-current", "page");
      else a.removeAttribute("aria-current");
    });
    if (!matched) {
      root.appendChild(h("div", { class: "container page" }, emptyState("Page not found", "That page does not exist.", h("a", { class: "btn btn-primary", href: "#/" }, "New check"))));
      root.setAttribute("aria-busy", "false");
      return;
    }
    Promise.resolve(matched.view(root, ctx, ...m.slice(1)))
      .catch((e) => {
        if (!ctx.alive()) return;
        if (e && e.status === 401) return;
        clear(root);
        root.appendChild(h("div", { class: "container page" }, emptyState("Something went wrong", (e && e.message) || String(e))));
      })
      .finally(() => { if (ctx.alive()) root.setAttribute("aria-busy", "false"); });
    window.scrollTo(0, 0);
  }

  function closeMobileNav() {
    const nl = $("#navlinks");
    if (nl) nl.classList.remove("open");
    const t = $("#nav-toggle");
    if (t) t.setAttribute("aria-expanded", "false");
  }

  function closeUserMenu() {
    const m = $("#user-menu");
    if (m) m.classList.add("hidden");
    const p = $("#user-pill");
    if (p) p.setAttribute("aria-expanded", "false");
  }

  function setupShell() {
    const u = S.user;
    $("#user-name").textContent = u.username;
    $("#user-avatar").textContent = (u.username || "?").slice(0, 1);
    $("#user-menu-label").textContent = `${u.username} · ${u.role === "admin" ? "Administrator" : "User"}`;
    const isAdmin = u.role === "admin";
    $("#nav-admin").classList.toggle("hidden", !isAdmin);
    $("#menu-admin").classList.toggle("hidden", !isAdmin);

    const pill = $("#user-pill");
    const menu = $("#user-menu");
    pill.addEventListener("click", () => {
      const open = menu.classList.contains("hidden");
      menu.classList.toggle("hidden", !open);
      pill.setAttribute("aria-expanded", String(open));
      if (open) { const f = focusables(menu)[0]; if (f) f.focus(); }
    });
    document.addEventListener("mousedown", (e) => {
      if (!menu.classList.contains("hidden") && !menu.contains(e.target) && !pill.contains(e.target)) closeUserMenu();
    });
    menu.addEventListener("keydown", (e) => {
      if (e.key === "Escape") { closeUserMenu(); pill.focus(); }
      if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        const items = focusables(menu);
        const i = items.indexOf(document.activeElement);
        const next = items[(i + (e.key === "ArrowDown" ? 1 : items.length - 1)) % items.length];
        if (next) next.focus();
        e.preventDefault();
      }
    });
    menu.addEventListener("click", (e) => { if (e.target.closest("a")) closeUserMenu(); });
    $("#btn-signout").addEventListener("click", async () => {
      try { await api("POST", "/api/auth/logout"); } catch (_) { /* ignore */ }
      location.href = "/login";
    });

    const toggle = $("#nav-toggle");
    toggle.addEventListener("click", () => {
      const nl = $("#navlinks");
      const open = !nl.classList.contains("open");
      nl.classList.toggle("open", open);
      toggle.setAttribute("aria-expanded", String(open));
    });
    $("#navlinks").addEventListener("click", (e) => { if (e.target.closest("a")) closeMobileNav(); });
  }

  async function boot() {
    let me;
    try {
      me = await api("GET", "/api/auth/me");
    } catch (e) {
      replace($("#app"), h("div", { class: "container page" }, emptyState("Cannot reach the server", e.message)));
      return;
    }
    if (!me || !me.user) { toLogin(false); return; }
    S.user = me.user;
    S.csrf = me.csrf;
    setupShell();
    window.addEventListener("hashchange", route);
    route();
  }

  // ════════════════════════════════════════════════════════════════════
  // 5a. View: New check
  // ════════════════════════════════════════════════════════════════════

  const COMPANION_EXTS = ["bib", "bbl"];

  /** Mirror of the server's pairing rule (API.md, POST /api/runs). */
  function computePairing(files) {
    const pdfs = files.filter((f) => fileExt(f.name) === "pdf");
    const comps = files.filter((f) => COMPANION_EXTS.includes(fileExt(f.name)));
    const pairOf = new Map(); // pdf File -> companion File
    const pairedComp = new Set();
    for (const p of pdfs) {
      const stem = fileStem(p.name);
      // Same-stem .bib is preferred over .bbl (richer fields), like the server.
      const sameStem = (ext) => comps.find((x) => !pairedComp.has(x) && fileStem(x.name) === stem && fileExt(x.name) === ext);
      const c = sameStem("bib") || sameStem("bbl");
      if (c) { pairOf.set(p, c); pairedComp.add(c); }
    }
    if (pdfs.length === 1 && comps.length === 1 && !pairOf.size) {
      pairOf.set(pdfs[0], comps[0]);
      pairedComp.add(comps[0]);
    }
    return { pairOf, pairedComp };
  }

  function viewNew(root, ctx) {
    const st = {
      files: [],
      bibMode: "merge",
      dbChecked: {},
      urlMatch: false,
      searxng: false,
      openalexAuthors: false,
      title: "",
      uploading: false,
    };

    const fileInput = h("input", { type: "file", multiple: true, class: "sr-only", tabindex: "-1", "aria-hidden": "true" });
    const dz = h("div", { class: "dropzone", role: "button", tabindex: "0", "aria-label": "Choose files to check, or drop them here" },
      h("div", { class: "dz-icon", "aria-hidden": "true" }, "↑"),
      h("div", { class: "dz-title" }, "Drop papers here or click to browse"),
      h("p", { class: "caption mt-sm", id: "dz-accept" }, "PDF, BibTeX (.bib), .bbl, GROBID .xml, or a .zip / .tar.gz archive of them"));
    const fileListEl = h("ul", { class: "file-list", "aria-label": "Selected files" });
    const pairingEl = h("div", { class: "mt-md" });
    const optionsEl = h("div", { class: "stack" }, skeleton(1));
    const errEl = h("p", { class: "field-error hidden", role: "alert" });
    const uploadProg = h("div", { class: "hidden stack mt-md" });
    const submitBtn = h("button", { type: "submit", class: "btn btn-primary", disabled: true }, "Start check");
    const clearBtn = h("button", { type: "button", class: "btn btn-tertiary hidden", onclick: () => { st.files = []; renderFiles(); } }, "Clear");
    const summaryEl = h("span", { class: "caption" });

    const form = h("form", { class: "card upload-card", novalidate: true, onsubmit: onSubmit },
      fileInput, dz, fileListEl, pairingEl,
      h("details", { class: "options-panel" }, h("summary", null, "Options"), h("div", { class: "mt-md" }, optionsEl)),
      errEl, uploadProg,
      h("div", { class: "row-between mt-xl" }, summaryEl, h("div", { class: "btn-group" }, clearBtn, submitBtn)));

    const recentEl = h("div", null, skeleton(2));

    const page = h("div", { class: "container page" },
      h("section", { class: "hero" },
        h("h1", { class: "hero-display" }, "Every reference, verified."),
        h("p", { class: "subtitle" }, "Upload a paper and Hallucinator checks each citation against CrossRef, arXiv, DBLP, Semantic Scholar and a dozen more bibliographic databases."),
        h("p", { class: "disclaimer" }, "Detections are leads to verify, not proof: a reference that is “not found” may simply be missing from the databases checked. Confirm every flag by hand.")),
      form,
      h("section", { class: "section" },
        h("div", { class: "product-grid" },
          productCard("pc-coral", "Check", "Every citation", "Upload PDFs or bibliographies; results stream in live.", "#/", () => { dz.focus(); dz.scrollIntoView({ behavior: "smooth", block: "center" }); }),
          productCard("pc-magenta", "History", "Every run, kept", "Re-open past checks, mark false positives, export reports.", "#/history"),
          productCard("pc-blue", "Databases", "Offline indexes", "See how fresh DBLP, arXiv, ACL and the local corpus are.", "#/databases"),
          productCard("pc-purple", "BibTeX", ".bib support", "Pair a PDF with its .bib to recover titles, DOIs and URLs the PDF parser misses.", "#/", () => { dz.focus(); dz.scrollIntoView({ behavior: "smooth", block: "center" }); }))),
      h("section", { class: "section" },
        h("div", { class: "section-head" }, h("h2", { class: "section-title" }, "Recent runs"), h("a", { class: "btn-link", href: "#/history" }, "View all →")),
        recentEl));
    root.appendChild(page);

    // ── file handling ────────────────────────────────────────────────
    dz.addEventListener("click", () => fileInput.click());
    dz.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); fileInput.click(); } });
    fileInput.addEventListener("change", () => { addFiles(Array.from(fileInput.files || [])); fileInput.value = ""; });
    ["dragenter", "dragover"].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add("drag"); }));
    ["dragleave", "dragend"].forEach((ev) => dz.addEventListener(ev, () => dz.classList.remove("drag")));
    dz.addEventListener("drop", (e) => {
      e.preventDefault();
      dz.classList.remove("drag");
      addFiles(Array.from((e.dataTransfer && e.dataTransfer.files) || []));
    });
    // Allow dropping anywhere on the page without the browser navigating away.
    const stopNav = (e) => { if (e.dataTransfer && Array.from(e.dataTransfer.types || []).includes("Files")) e.preventDefault(); };
    window.addEventListener("dragover", stopNav);
    window.addEventListener("drop", stopNav);
    ctx.on(() => { window.removeEventListener("dragover", stopNav); window.removeEventListener("drop", stopNav); });

    function acceptedExts() {
      const acc = (S.options && S.options.accepted) || [".pdf", ".bib", ".bbl", ".xml", ".zip", ".tar.gz", ".tgz"];
      return acc.map((a) => a.toLowerCase());
    }

    function addFiles(list) {
      const acc = acceptedExts();
      const rejected = [];
      for (const f of list) {
        const lower = f.name.toLowerCase();
        if (!acc.some((ext) => lower.endsWith(ext))) { rejected.push(f.name); continue; }
        if (st.files.some((x) => x.name === f.name && x.size === f.size)) continue;
        st.files.push(f);
      }
      if (rejected.length) toast(`Unsupported file type: ${rejected.join(", ")}`, "error");
      renderFiles();
    }

    function renderFiles() {
      clear(fileListEl);
      const { pairOf, pairedComp } = computePairing(st.files);
      const pairedTo = new Map();
      for (const [p, c] of pairOf) pairedTo.set(c, p);
      const merge = st.bibMode === "merge";
      for (const f of st.files) {
        const ext = fileExt(f.name);
        let pairText = null;
        if (pairOf.has(f)) pairText = merge ? `↔ paired with ${pairOf.get(f).name}` : `${pairOf.get(f).name} will be checked separately`;
        else if (pairedComp.has(f)) pairText = merge ? `↔ fills in references for ${pairedTo.get(f).name}` : "checked on its own (separate mode)";
        else if (COMPANION_EXTS.includes(ext) || ext === "xml") pairText = "checked on its own (all entries)";
        else if (["zip", "tar.gz", "tgz"].includes(ext)) pairText = "archive — expanded on the server; same-stem .bib/.bbl inside are paired automatically";
        fileListEl.appendChild(h("li", { class: "file-item" },
          h("span", { class: "ext-tag " + (ext === "pdf" ? "pdf" : "") , "aria-hidden": "true" }, ext.replace("tar.gz", "tgz")),
          h("div", { class: "grow" },
            h("div", { class: "fi-name" }, f.name),
            h("div", { class: "fi-meta" }, fmtBytes(f.size)),
            pairText ? h("div", { class: "fi-pair" }, pairText) : null),
          h("button", { type: "button", class: "btn-icon", "aria-label": `Remove ${f.name}`, onclick: () => { st.files = st.files.filter((x) => x !== f); renderFiles(); } }, "×")));
      }
      // pairing / bib_mode panel
      clear(pairingEl);
      if (pairOf.size) {
        const seg = h("div", { class: "pill-tabs", role: "radiogroup", "aria-label": "How to use the paired .bib/.bbl" },
          modePill("merge", "Merge into the PDF (recommended)"),
          modePill("separate", "Check each file separately"));
        pairingEl.appendChild(h("div", { class: "info-box stack" },
          h("strong", { class: "small" }, `${plural(pairOf.size, "PDF")} paired with a bibliography file`),
          h("p", { class: "small" }, "In merge mode the PDF decides which references are actually cited, and the .bib/.bbl fills in clean titles, authors, DOIs, arXiv IDs and URLs that the PDF parser can miss. Uncited .bib entries are ignored; references with no .bib match keep the PDF parse."),
          seg));
      }
      const total = st.files.reduce((a, f) => a + f.size, 0);
      const maxMb = (S.options && S.options.max_upload_mb) || 0;
      const tooBig = maxMb > 0 && total > maxMb * 1024 * 1024;
      summaryEl.textContent = st.files.length ? `${plural(st.files.length, "file")} · ${fmtBytes(total)}${tooBig ? ` — exceeds the ${maxMb} MB upload limit` : ""}` : "";
      summaryEl.classList.toggle("field-error", tooBig);
      submitBtn.disabled = !st.files.length || tooBig || st.uploading;
      clearBtn.classList.toggle("hidden", !st.files.length);
    }

    function modePill(mode, label) {
      return h("button", {
        type: "button", class: "pill-tab", role: "radio", "aria-checked": String(st.bibMode === mode), "aria-pressed": String(st.bibMode === mode),
        onclick: () => { st.bibMode = mode; renderFiles(); },
      }, label);
    }

    // ── options ──────────────────────────────────────────────────────
    loadOptions().then((opt) => {
      if (!ctx.alive()) return;
      const defaults = opt.defaults || {};
      const disabled = new Set(defaults.disabled_dbs || []);
      for (const d of opt.databases || []) st.dbChecked[d.name] = d.available !== false && !disabled.has(d.name);
      st.urlMatch = !!defaults.url_match;
      st.searxng = !!defaults.searxng && !!opt.searxng_configured;
      st.openalexAuthors = !!defaults.check_openalex_authors;
      if (opt.accepted && opt.accepted.length) $("#dz-accept", dz).textContent = "Accepted: " + opt.accepted.join(", ") + (opt.max_upload_mb ? ` · up to ${opt.max_upload_mb} MB` : "");
      fileInput.setAttribute("accept", (opt.accepted || []).join(","));
      renderOptions(opt);
      renderFiles();
    }).catch((e) => { replace(optionsEl, h("p", { class: "field-error" }, e.message)); });

    function renderOptions(opt) {
      const dbBoxes = h("div", { class: "db-grid" });
      const renderBoxes = () => {
        clear(dbBoxes);
        for (const d of opt.databases || []) {
          const unavailable = d.available === false;
          dbBoxes.appendChild(h("div", { class: "db-opt" },
            h("label", { class: "check" },
              h("input", { type: "checkbox", checked: !!st.dbChecked[d.name], disabled: unavailable, onchange: (e) => { st.dbChecked[d.name] = e.target.checked; } }),
              h("span", null, d.name),
              d.offline ? badge("offline", "badge-code") : null,
              unavailable ? badge("unavailable", "badge-muted badge-sm") : null),
            d.note ? h("span", { class: "note" }, d.note) : null));
        }
      };
      renderBoxes();
      const urlSw = switchEl("Cross-check unmatched references by URL liveness (URL check + Wayback)", { checked: st.urlMatch, onchange: (e) => { st.urlMatch = e.target.checked; } });
      const sxSw = switchEl("Web search fallback (SearxNG)" + (opt.searxng_configured ? "" : " — not configured on this server"), { checked: st.searxng, disabled: !opt.searxng_configured, onchange: (e) => { st.searxng = e.target.checked; } });
      const oaSw = switchEl("Flag author mismatches reported by OpenAlex", { checked: st.openalexAuthors, onchange: (e) => { st.openalexAuthors = e.target.checked; } });
      const titleIn = h("input", { class: "input", placeholder: "Defaults to the first file name", maxlength: "200", oninput: (e) => { st.title = e.target.value; } });
      replace(optionsEl,
        h("label", { class: "field" }, h("span", null, "Run title (optional)"), titleIn),
        h("div", { class: "stack" },
          h("div", { class: "row-between" },
            h("span", { class: "label" }, "Databases"),
            h("div", { class: "btn-group" },
              h("button", { type: "button", class: "btn-link", onclick: () => { for (const d of opt.databases || []) if (d.available !== false) st.dbChecked[d.name] = true; renderBoxes(); } }, "Select all"),
              h("span", { class: "stone", "aria-hidden": "true" }, "·"),
              h("button", { type: "button", class: "btn-link", onclick: () => { const dis = new Set((opt.defaults || {}).disabled_dbs || []); for (const d of opt.databases || []) st.dbChecked[d.name] = d.available !== false && !dis.has(d.name); renderBoxes(); } }, "Reset to defaults"))),
          dbBoxes),
        h("div", { class: "stack" }, h("span", { class: "label" }, "Checks"), urlSw.el, sxSw.el, oaSw.el),
        opt.defaults && opt.defaults.num_workers ? h("p", { class: "caption" }, `The server checks ${opt.defaults.num_workers} references in parallel per run.`) : null);
    }

    // ── submit ───────────────────────────────────────────────────────
    function onSubmit(e) {
      e.preventDefault();
      if (!st.files.length || st.uploading) return;
      errEl.classList.add("hidden");
      const opt = S.options || { databases: [] };
      const options = {
        disabled_dbs: (opt.databases || []).filter((d) => !st.dbChecked[d.name]).map((d) => d.name),
        url_match: st.urlMatch,
        searxng: st.searxng,
        check_openalex_authors: st.openalexAuthors,
        bib_mode: st.bibMode,
      };
      if (st.title.trim()) options.title = st.title.trim();
      const fd = new FormData();
      for (const f of st.files) fd.append("files", f, f.name);
      fd.append("options", JSON.stringify(options));

      st.uploading = true;
      submitBtn.disabled = true;
      submitBtn.textContent = "Uploading…";
      const pctText = h("span", { class: "caption" }, "Uploading… 0%");
      const bar = progressBar(0, "lg");
      replace(uploadProg, pctText, bar);
      uploadProg.classList.remove("hidden");

      const xhr = new XMLHttpRequest();
      xhr.open("POST", "/api/runs");
      xhr.setRequestHeader("X-CSRF-Token", S.csrf || "");
      xhr.setRequestHeader("Accept", "application/json");
      xhr.upload.onprogress = (ev) => {
        if (!ev.lengthComputable) return;
        const f = ev.loaded / ev.total;
        $(".bar", bar).style.width = (f * 100).toFixed(1) + "%";
        bar.setAttribute("aria-valuenow", String(Math.round(f * 100)));
        pctText.textContent = f >= 1 ? "Processing upload…" : `Uploading… ${Math.round(f * 100)}%`;
      };
      const done = (msg) => {
        st.uploading = false;
        submitBtn.textContent = "Start check";
        uploadProg.classList.add("hidden");
        if (msg) { errEl.textContent = msg; errEl.classList.remove("hidden"); }
        renderFiles();
      };
      xhr.onload = () => {
        let data = null;
        try { data = JSON.parse(xhr.responseText || "null"); } catch (_) { data = null; }
        if (xhr.status === 401) { toLogin(true); return; }
        if (xhr.status >= 200 && xhr.status < 300 && data && data.run_id) {
          location.hash = "#/runs/" + encodeURIComponent(data.run_id);
          return;
        }
        done((data && data.error) || (xhr.status === 413 ? "The upload is too large." : `Upload failed (HTTP ${xhr.status}).`));
      };
      xhr.onerror = () => done("Network error — the upload did not reach the server.");
      xhr.send(fd);
    }

    // ── recent runs ──────────────────────────────────────────────────
    api("GET", "/api/runs?limit=5").then((data) => {
      if (!ctx.alive()) return;
      const runs = (data && data.runs) || [];
      if (!runs.length) { replace(recentEl, emptyState("No runs yet", "Your checks will appear here.")); return; }
      replace(recentEl, runsTable(runs, false));
    }).catch((e) => replace(recentEl, h("p", { class: "field-error" }, e.message)));
  }

  function productCard(cls, kicker, title, tag, href, onClick) {
    const a = h("a", { class: "product-card " + cls, href },
      h("span", { class: "pc-kicker" }, kicker),
      h("div", null, h("div", { class: "pc-title" }, title), h("p", { class: "pc-tag mt-sm" }, tag)));
    if (onClick) a.addEventListener("click", (e) => { e.preventDefault(); onClick(); });
    return a;
  }

  /** Table of RunSummary rows (history + recent runs). */
  function runsTable(runs, showUser) {
    const tbody = h("tbody");
    for (const r of runs) {
      const st = r.stats || {};
      const go = () => { location.hash = "#/runs/" + encodeURIComponent(r.id); };
      tbody.appendChild(h("tr", { class: "clickable", tabindex: "0", onclick: go, onkeydown: (e) => { if (e.key === "Enter") go(); } },
        h("td", null, h("div", { class: "t-title" }, r.title || r.id), r.error ? h("div", { class: "t-sub" }, r.error) : null),
        h("td", { class: "num" }, fmtNum(r.paper_count)),
        h("td", { class: "num nowrap" },
          h("span", { class: st.problems ? "text-bad" : "" }, fmtNum(st.problems || 0)),
          h("span", { class: "stone" }, " / " + fmtNum(st.total || 0))),
        h("td", null, runStatusBadge(r.status)),
        h("td", { class: "nowrap" }, timeEl(r.created_at)),
        showUser ? h("td", null, r.username || "—") : null));
    }
    return h("div", { class: "table-wrap" }, h("table", { class: "data" },
      h("thead", null, h("tr", null,
        h("th", null, "Title"), h("th", { class: "num" }, "Papers"), h("th", { class: "num" }, "Problems / Total"),
        h("th", null, "Status"), h("th", null, "Created"), showUser ? h("th", null, "User") : null)),
      tbody));
  }

  // ════════════════════════════════════════════════════════════════════
  // 5b. View: Run
  // ════════════════════════════════════════════════════════════════════

  const REF_FILTERS = [
    { key: "all", label: "All", test: () => true },
    { key: "problems", label: "Problems", test: isProblem },
    { key: "not_found", label: "Not found", test: (r) => !r.fp_reason && r.verdict === "not_found" },
    { key: "mismatch", label: "Mismatch", test: (r) => !r.fp_reason && r.verdict === "mismatch" },
    { key: "inconclusive", label: "Inconclusive", test: (r) => !r.fp_reason && r.verdict === "inconclusive" },
    { key: "verified", label: "Verified", test: (r) => !r.fp_reason && r.verdict === "verified" },
    { key: "skipped", label: "Skipped", test: (r) => r.phase === "skipped" || r.verdict === "skipped" },
    { key: "safe", label: "Marked safe", test: (r) => !!r.fp_reason },
  ];

  const runViewPrefs = { filter: "all", sort: "num" };

  function viewRun(root, ctx, rawId) {
    const id = decodeURIComponent(rawId);
    const base = `/api/runs/${encodeURIComponent(id)}`;
    const rv = {
      run: null,
      papers: [],
      sel: 0,
      selRef: null,
      filter: runViewPrefs.filter,
      sort: runViewPrefs.sort,
      q: "",
      es: null,
      ended: false,
      backoff: 1000,
      reconnectTimer: null,
      dirty: {},
      flushTimer: null,
      built: false,
      drawer: null,
      noticeToasts: [],
      countEls: {},
      busy: false,
    };

    root.appendChild(h("div", { class: "container page" }, skeleton(4)));

    // ── layout elements (built on first snapshot) ────────────────────
    const headEl = h("div", { class: "run-head" });
    const runProgEl = h("div");
    const statsEl = h("div", { class: "mt-md" });
    const runBannerEl = h("div", { class: "stack mt-md" });
    const papersEl = h("nav", { class: "run-papers", "aria-label": "Papers in this run" });
    const paperBarEl = h("div", { class: "paper-bar" });
    const bannersEl = h("div", { class: "stack", style: { marginBottom: "12px" } });
    const toolbarEl = h("div");
    const tableEl = h("div");
    const detailEl = h("aside", { class: "run-detail docked", "aria-label": "Reference detail" });

    function buildLayout() {
      rv.built = true;
      replace(root, h("div", { class: "container page" },
        headEl, runProgEl, statsEl, runBannerEl, papersEl,
        h("div", { class: "run-layout" },
          h("section", { class: "run-main", "aria-label": "References" }, paperBarEl, bannersEl, toolbarEl, tableEl),
          detailEl)));
    }

    function paper() { return rv.papers[rv.sel] || null; }
    function findPaper(idx) { return rv.papers.find((p) => p.idx === idx) || null; }
    function findRef(p, idx) { return p && p.refs ? p.refs.find((r) => r.idx === idx) || null : null; }
    function selectedRef() { return rv.selRef == null ? null : findRef(paper(), rv.selRef); }
    function runActive() { return rv.run && (rv.run.status === "queued" || rv.run.status === "running"); }

    function schedule(...parts) {
      for (const p of parts) rv.dirty[p] = true;
      if (!rv.flushTimer) rv.flushTimer = setTimeout(flush, 120);
    }

    function flush() {
      rv.flushTimer = null;
      if (!ctx.alive() || !rv.run) return;
      if (!rv.built) buildLayout();
      const d = rv.dirty;
      rv.dirty = {};
      if (d.head) renderHead();
      if (d.stats) renderStats();
      if (d.papers) renderPapers();
      if (d.paper) renderPaperBar();
      if (d.toolbar) renderToolbar();
      if (d.table) renderTable();
      if (d.detail) renderDetailPanel();
    }

    const ALL = ["head", "stats", "papers", "paper", "toolbar", "table", "detail"];

    // ── SSE ──────────────────────────────────────────────────────────
    function connect() {
      if (!ctx.alive()) return;
      if (rv.es) rv.es.close();
      clearTimeout(rv.reconnectTimer);
      rv.ended = false;
      const es = new EventSource(`${base}/events`);
      rv.es = es;
      const on = (name, fn) => es.addEventListener(name, (ev) => {
        if (!ctx.alive()) return;
        let data = null;
        try { data = JSON.parse(ev.data); } catch (_) { return; }
        fn(data);
      });
      on("snapshot", (d) => { rv.backoff = 1000; applySnapshot(d); });
      on("run", (d) => {
        if (!rv.run) return;
        Object.assign(rv.run, d);
        schedule("head", "stats", "paper");
      });
      on("paper", (d) => {
        const p = findPaper(d.paper_idx);
        if (!p) return;
        for (const k of ["status", "error", "stats", "verdict", "merge", "skip_stats", "input_kind"]) if (k in d) p[k] = d[k];
        schedule("stats", "papers");
        if (p === paper()) schedule("paper", "table");
      });
      on("refs", (d) => {
        const p = findPaper(d.paper_idx);
        if (!p) return;
        p.refs = d.refs || [];
        schedule("papers");
        if (p === paper()) schedule("table", "toolbar", "detail");
      });
      on("ref", (d) => {
        const p = findPaper(d.paper_idx);
        if (!p || !d.ref) return;
        upsertRef(p, d.ref);
        if (d.stats) p.stats = d.stats;
        schedule("stats", "papers");
        if (p === paper()) {
          schedule("table");
          if (d.ref.idx === rv.selRef) schedule("detail");
        }
      });
      on("db", (d) => {
        const p = findPaper(d.paper_idx);
        const r = findRef(p, d.ref_idx);
        if (!r) return;
        if (r.phase === "pending") r.phase = "checking";
        r.live_dbs = r.live_dbs || [];
        const ex = r.live_dbs.find((x) => x.db === d.db);
        if (ex) { ex.status = d.status; ex.elapsed_ms = d.elapsed_ms; }
        else r.live_dbs.push({ db: d.db, status: d.status, elapsed_ms: d.elapsed_ms });
        if (p === paper()) {
          schedule("table");
          if (r.idx === rv.selRef) schedule("detail");
        }
      });
      on("notice", (d) => {
        rv.noticeToasts.push(toast(d.message, d.level === "error" ? "error" : "", d.level === "error" ? 10000 : 5000));
        runBannerEl.appendChild(h("div", { class: "banner " + (d.level === "error" ? "banner-error" : d.level === "warn" ? "banner-warn" : "banner-info") },
          h("span", { class: "grow break" }, d.message)));
      });
      on("end", () => {
        rv.ended = true;
        es.close();
        schedule("head", "stats", "paper");
      });
      es.onerror = () => {
        if (!ctx.alive()) return;
        es.close();
        if (rv.ended) return;
        // Find out whether the run still exists / we're still signed in
        // before hammering the stream again.
        api("GET", base).then((detail) => {
          if (!ctx.alive()) return;
          applySnapshot(detail);
          const terminal = !runActive();
          if (terminal) { rv.ended = true; return; }
          rv.reconnectTimer = setTimeout(connect, rv.backoff);
          rv.backoff = Math.min(rv.backoff * 2, 15000);
        }).catch((e) => {
          if (!ctx.alive() || e.status === 401) return;
          if (e.status === 404 || e.status === 403) {
            rv.ended = true;
            replace(root, h("div", { class: "container page" }, emptyState(e.status === 404 ? "Run not found" : "Not allowed", e.message, h("a", { class: "btn btn-primary", href: "#/history" }, "Back to history"))));
            return;
          }
          rv.reconnectTimer = setTimeout(connect, rv.backoff);
          rv.backoff = Math.min(rv.backoff * 2, 15000);
        });
      };
    }

    function upsertRef(p, ref) {
      p.refs = p.refs || [];
      const i = p.refs.findIndex((r) => r.idx === ref.idx);
      if (i >= 0) p.refs[i] = ref;
      else { p.refs.push(ref); p.refs.sort((a, b) => a.idx - b.idx); }
    }

    function applySnapshot(d) {
      if (!d || !d.run) return;
      const prevSelIdx = paper() ? paper().idx : null;
      rv.run = d.run;
      rv.papers = (d.papers || []).slice().sort((a, b) => a.idx - b.idx);
      const i = prevSelIdx == null ? 0 : rv.papers.findIndex((p) => p.idx === prevSelIdx);
      rv.sel = i >= 0 ? i : 0;
      if (rv.selRef != null && !selectedRef()) rv.selRef = null;
      document.title = `${rv.run.title || "Run"} · Hallucinator`;
      schedule(...ALL);
      if (!rv.built) flush();
    }

    ctx.on(() => {
      if (rv.es) rv.es.close();
      clearTimeout(rv.reconnectTimer);
      clearTimeout(rv.flushTimer);
      closeDrawer();
      for (const t of rv.noticeToasts) t.remove();
      document.removeEventListener("keydown", onKey);
      document.title = "Hallucinator";
    });

    // ── header ───────────────────────────────────────────────────────
    function runStats() {
      return rv.papers.length ? sumStats(rv.papers.map((p) => p.stats)) : (rv.run.stats || {});
    }

    function renderHead() {
      const r = rv.run;
      const actions = h("div", { class: "btn-group" });
      if (runActive()) {
        actions.appendChild(h("button", { type: "button", class: "btn btn-secondary btn-sm", onclick: cancelRun }, "Cancel"));
      }
      actions.appendChild(exportMenu().root);
      actions.appendChild(h("button", { type: "button", class: "btn btn-tertiary btn-sm", onclick: deleteRun }, "Delete"));
      const meta = h("div", { class: "row mt-sm" },
        runStatusBadge(r.status),
        h("span", { class: "caption" }, plural(r.paper_count || rv.papers.length, "paper")),
        h("span", { class: "caption" }, "· created ", timeEl(r.created_at)),
        r.finished_at ? h("span", { class: "caption" }, "· finished ", timeEl(r.finished_at)) : null,
        r.started_at && r.finished_at ? h("span", { class: "caption" }, `· took ${fmtDuration(r.finished_at - r.started_at)}`) : null,
        r.username && S.user && r.username !== S.user.username ? h("span", { class: "caption" }, `· by ${r.username}`) : null);
      replace(headEl,
        h("div", { class: "grow" },
          h("a", { class: "btn-link", href: "#/history" }, "← History"),
          h("h1", null, breakableName(r.title || "Run")),
          meta),
        actions);
      // run-level error banner (kept separate from notices)
      const errId = "run-error-banner";
      const old = document.getElementById(errId);
      if (old) old.remove();
      if (r.error) runBannerEl.prepend(h("div", { class: "banner banner-error", id: errId }, h("strong", null, "Run failed: "), h("span", { class: "break" }, r.error)));
      if (r.status === "interrupted" && !document.getElementById("run-int-banner")) {
        runBannerEl.prepend(h("div", { class: "banner banner-warn", id: "run-int-banner" }, "The server restarted while this run was in progress. References without a result were not checked — use “Re-check” on a paper to finish them."));
      }
    }

    function renderStats() {
      const st = runStats();
      replace(statsEl, statsStrip(st));
      clear(runProgEl);
      if (runActive()) {
        const denom = (st.checked || 0) + (st.pending || 0);
        runProgEl.appendChild(h("div", { class: "stack mt-md" },
          h("div", { class: "row-between caption" },
            h("span", null, denom ? `Checked ${fmtNum(st.checked)} of ${fmtNum(denom)} references` : "Extracting references…"),
            denom ? h("span", null, Math.round((100 * st.checked) / denom) + "%") : null),
          outcomeBar(st, "lg")));
      }
    }

    function exportMenu() {
      const exp = { format: "json", scope: "run", problematic: false };
      return dropdown("Export", (close) => {
        const link = h("a", { class: "btn btn-primary btn-sm", download: "", onclick: () => setTimeout(close, 0) }, "Download");
        const update = () => {
          const params = new URLSearchParams({ format: exp.format, problematic: exp.problematic ? "1" : "0" });
          const p = paper();
          if (exp.scope === "paper" && p) params.set("paper", String(p.idx));
          link.setAttribute("href", `${base}/export?${params.toString()}`);
        };
        const fmtSel = h("select", { class: "input input-sm", "aria-label": "Format", onchange: (e) => { exp.format = e.target.value; update(); } },
          [["json", "JSON (loadable by hallucinator-tui)"], ["csv", "CSV"], ["markdown", "Markdown"], ["text", "Plain text"], ["html", "HTML"]]
            .map(([v, l]) => h("option", { value: v, selected: v === exp.format }, l)));
        const scopeSel = h("select", { class: "input input-sm", "aria-label": "Scope", onchange: (e) => { exp.scope = e.target.value; update(); } },
          h("option", { value: "run" }, "Whole run"),
          paper() ? h("option", { value: "paper" }, "Current paper only") : null);
        const prob = h("label", { class: "check" }, h("input", { type: "checkbox", onchange: (e) => { exp.problematic = e.target.checked; update(); } }), "Problems only");
        update();
        return h("div", { class: "stack", style: { padding: "8px", minWidth: "240px" } },
          h("div", { class: "menu-label" }, "Export results"),
          h("label", { class: "field" }, h("span", null, "Format"), fmtSel),
          h("label", { class: "field" }, h("span", null, "Scope"), scopeSel),
          prob, link);
      });
    }

    async function cancelRun() {
      try { await api("POST", `${base}/cancel`); toast("Cancelling run…"); }
      catch (e) { showError(e); }
    }

    async function deleteRun() {
      const ok = await confirmDialog({
        title: "Delete this run?",
        message: "The run, its results and any false-positive marks will be permanently deleted. This cannot be undone.",
        confirmLabel: "Delete run",
        danger: true,
      });
      if (!ok) return;
      try {
        await api("DELETE", base);
        toast("Run deleted.", "success");
        location.hash = "#/history";
      } catch (e) { showError(e); }
    }

    // ── papers ───────────────────────────────────────────────────────
    function renderPapers() {
      const grid = h("div", { class: "paper-grid" + (rv.papers.length > 8 ? " many" : "") });
      rv.papers.forEach((p, i) => grid.appendChild(paperCard(p, i)));
      replace(papersEl,
        h("div", { class: "run-papers-head" }, h("span", { class: "label" }, `Papers (${rv.papers.length})`), outcomeLegend()),
        grid);
    }

    function paperCard(p, i) {
      const st = p.stats || {};
      const denom = (st.checked || 0) + (st.pending || 0);
      const active = p.status === "queued" || p.status === "extracting" || p.status === "checking";
      let progress;
      if (denom) {
        progress = h("span", null, h("strong", null, fmtNum(st.checked)), ` / ${fmtNum(denom)} checked`,
          active ? ` · ${Math.round((100 * st.checked) / denom)}%` : "");
      } else {
        progress = h("span", null, { queued: "Waiting…", extracting: "Extracting references…", failed: "Extraction failed" }[p.status] || "No references");
      }
      let outcome = null;
      if (st.problems) outcome = h("span", { class: "text-bad nowrap" }, plural(st.problems, "problem"));
      else if (p.status === "done" && denom) outcome = h("span", { class: "text-good nowrap" }, "No problems");
      return h("button", {
        type: "button", class: "paper-card", "aria-current": String(i === rv.sel), title: p.filename,
        onclick: () => selectPaper(i),
      },
        h("span", { class: "pp-name" }, breakableName(p.filename)),
        h("span", { class: "pp-sub" },
          h("span", { class: "row" }, kindBadge(p.input_kind),
            p.companion_filename ? h("span", { class: "truncate" }, `with ${p.companion_filename}`) : null),
          paperStatusBadge(p.status)),
        outcomeBar(st),
        h("span", { class: "pp-foot" }, progress, outcome));
    }

    function selectPaper(i) {
      if (i === rv.sel) return;
      rv.sel = i;
      rv.selRef = null;
      rv.q = "";
      closeDrawer();
      schedule("papers", "paper", "toolbar", "table", "detail");
      flush();
    }

    // ── paper bar & banners ──────────────────────────────────────────
    function renderPaperBar() {
      const p = paper();
      clear(bannersEl);
      if (!p) { replace(paperBarEl, emptyState("No papers", "This run has no papers.")); return; }
      const verdictT = h("div", { class: "verdict-toggle", role: "group", "aria-label": "Paper verdict" },
        verdictBtn(p, "safe", "Safe"), verdictBtn(p, "questionable", "Questionable"));
      const retry = dropdown("Re-check", (close) => [
        menuBtn("Re-check failed databases", "Only databases that timed out or errored", () => { close(); retryPaper("failed"); }),
        menuBtn("Re-check not found", "Full re-check of every not-found reference", () => { close(); retryPaper("not_found"); }),
        menuBtn("Re-check all problems", "Not found, mismatches and retracted", () => { close(); retryPaper("problems"); }),
      ], { disabled: runActive() || p.status === "failed" });
      replace(paperBarEl,
        h("div", { class: "grow" },
          h("div", { class: "paper-title" }, breakableName(p.filename)),
          h("div", { class: "row mt-sm" },
            kindBadge(p.input_kind),
            p.companion_filename ? h("span", { class: "caption" }, `with ${p.companion_filename}`) : null,
            paperStatusBadge(p.status))),
        h("div", { class: "row" }, verdictT, retry.root));

      if (p.status === "failed" && p.error) {
        bannersEl.appendChild(h("div", { class: "banner banner-error" }, h("strong", null, "Extraction failed: "), h("span", { class: "break" }, p.error)));
      } else if (p.error) {
        bannersEl.appendChild(h("div", { class: "banner banner-warn" }, h("span", { class: "break" }, p.error)));
      }
      const m = p.merge;
      if (m) {
        if (m.fallback) {
          const why = m.fallback === "pdf_empty" ? "No references were found in the PDF" : "The PDF could not be parsed";
          bannersEl.appendChild(h("div", { class: "banner banner-warn" },
            h("span", null, `${why}, so all ${fmtNum(m.companion_entries)} entries of ${m.companion} were checked instead (uncited entries may be included).`)));
        } else {
          const ignored = Math.max(0, (m.companion_entries || 0) - (m.matched || 0));
          bannersEl.appendChild(h("div", { class: "banner banner-info" },
            h("span", null,
              h("strong", null, `${fmtNum(m.matched)} of ${fmtNum(m.pdf_refs)}`),
              ` references enriched from ${m.companion}`,
              m.pdf_only ? ` · ${fmtNum(m.pdf_only)} PDF-only` : "",
              ignored ? ` · ${plural(ignored, "entry", "entries")} of the .bib not matched to a cited reference (not checked)` : "")));
        }
      }
      const ss = p.skip_stats;
      if (ss) {
        const parts = [];
        if (ss.url_only) parts.push(`${fmtNum(ss.url_only)} URL-only`);
        if (ss.short_title) parts.push(`${fmtNum(ss.short_title)} with a short title`);
        if (ss.no_title) parts.push(`${fmtNum(ss.no_title)} without a title`);
        const raw = ss.total_raw ? `${fmtNum(ss.total_raw)} raw references extracted` : null;
        if (parts.length || raw) {
          bannersEl.appendChild(h("p", { class: "caption" }, [raw, parts.length ? `skipped: ${parts.join(", ")}` : null].filter(Boolean).join(" · "),
            ss.no_authors ? ` · ${fmtNum(ss.no_authors)} without parsed authors` : ""));
        }
      }
    }

    function menuBtn(label, sub, onclick) {
      return h("button", { type: "button", class: "menu-item", role: "menuitem", onclick },
        h("span", { class: "stack", style: { gap: "0" } }, h("span", null, label), sub ? h("span", { class: "micro" }, sub) : null));
    }

    function verdictBtn(p, v, label) {
      return h("button", {
        type: "button", class: v, "aria-pressed": String(p.verdict === v),
        onclick: async () => {
          const next = p.verdict === v ? null : v;
          try {
            await api("PUT", `${base}/papers/${p.idx}/verdict`, { verdict: next });
            p.verdict = next;
            schedule("paper");
          } catch (e) { showError(e); }
        },
      }, label);
    }

    async function retryPaper(scope, refIdx) {
      const p = paper();
      if (!p) return;
      const body = { scope };
      if (scope === "ref") body.ref_idx = refIdx;
      try {
        const res = await api("POST", `${base}/papers/${p.idx}/retry`, body);
        const n = res && Number.isFinite(res.queued) ? res.queued : 0;
        toast(n ? `Re-checking ${plural(n, "reference")}…` : "Nothing to re-check.", n ? "" : "");
        if (n && (rv.ended || !rv.es || rv.es.readyState === 2)) connect();
      } catch (e) { showError(e); }
    }

    // ── toolbar & table ──────────────────────────────────────────────
    function renderToolbar() {
      const p = paper();
      clear(toolbarEl);
      rv.countEls = {};
      if (!p) return;
      const pills = h("div", { class: "pill-tabs pill-tabs-sm", role: "toolbar", "aria-label": "Filter references" });
      for (const f of REF_FILTERS) {
        const count = h("span", { class: "count" }, "0");
        rv.countEls[f.key] = count;
        pills.appendChild(h("button", {
          type: "button", class: "pill-tab", "aria-pressed": String(rv.filter === f.key), dataset: { filter: f.key },
          onclick: () => {
            rv.filter = f.key;
            runViewPrefs.filter = f.key;
            pills.querySelectorAll(".pill-tab").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.filter === f.key)));
            renderTable();
          },
        }, f.label, count));
      }
      const search = h("input", { class: "search-pill", type: "search", placeholder: "Search title, author, citation…", "aria-label": "Search references", value: rv.q });
      search.addEventListener("input", debounce(() => { rv.q = search.value; renderTable(); }, 150));
      const sortSel = h("select", { class: "search-pill", "aria-label": "Sort references", onchange: (e) => { rv.sort = e.target.value; runViewPrefs.sort = rv.sort; renderTable(); } },
        h("option", { value: "num", selected: rv.sort === "num" }, "Sort: number"),
        h("option", { value: "verdict", selected: rv.sort === "verdict" }, "Sort: verdict"));
      sortSel.style.flex = "0 0 auto";
      append(toolbarEl, h("div", { class: "toolbar" }, pills), h("div", { class: "toolbar" }, search, sortSel));
    }

    function visibleRefs() {
      const p = paper();
      if (!p || !p.refs) return [];
      const f = REF_FILTERS.find((x) => x.key === rv.filter) || REF_FILTERS[0];
      const q = rv.q.trim().toLowerCase();
      let refs = p.refs.filter((r) => f.test(r));
      if (q) {
        refs = refs.filter((r) => [r.title, r.raw_citation, (r.authors || []).join(" "), r.doi, r.arxiv_id]
          .some((s) => s && String(s).toLowerCase().includes(q)));
      }
      refs = refs.slice();
      if (rv.sort === "verdict") refs.sort((a, b) => severity(a) - severity(b) || a.original_number - b.original_number);
      else refs.sort((a, b) => a.original_number - b.original_number || a.idx - b.idx);
      return refs;
    }

    function renderTable() {
      const p = paper();
      if (!p) { clear(tableEl); return; }
      const all = p.refs || [];
      for (const f of REF_FILTERS) if (rv.countEls[f.key]) rv.countEls[f.key].textContent = String(all.filter(f.test).length);
      if (!all.length) {
        let msg = "References will appear here once extraction finishes.";
        if (p.status === "failed") msg = "No references could be extracted from this file.";
        else if (p.status === "done") msg = "No references were found in this file.";
        replace(tableEl, p.status === "queued" || p.status === "extracting" ? h("div", null, skeleton(3), h("p", { class: "caption mt-sm" }, msg)) : emptyState("No references", msg));
        return;
      }
      const refs = visibleRefs();
      if (!refs.length) {
        replace(tableEl, emptyState("Nothing matches", rv.q ? "Try a different search." : "No references in this category."));
        return;
      }
      const merged = String(p.input_kind || "").includes("+");
      const tbody = h("tbody");
      for (const r of refs) {
        const authors = r.authors || [];
        const authorText = authors.length > 3 ? `${authors.slice(0, 3).join(", ")} et al.` : authors.join(", ");
        const sel = r.idx === rv.selRef;
        const row = h("tr", {
          class: "clickable" + (sel ? " selected" : ""), tabindex: "0", dataset: { idx: String(r.idx) },
          "aria-selected": String(sel),
          onclick: () => selectRef(r.idx, true),
          onkeydown: (e) => { if (e.key === "Enter") { e.preventDefault(); selectRef(r.idx, true); } },
        },
          h("td", { class: "num stone" }, String(r.original_number)),
          h("td", null,
            h("div", { class: "t-title" }, r.title || h("span", { class: "stone" }, truncate(r.raw_citation, 140) || "(no title)")),
            authorText || (merged && r.origin) ? h("div", { class: "t-sub" },
              authorText,
              merged && r.origin ? h("span", null, authorText ? " · " : "", badge(r.origin.toUpperCase(), r.origin === "pdf" ? "badge-outline badge-sm" : "badge-code")) : null) : null),
          h("td", null, h("div", { class: "row" }, verdictBadges(r))),
          h("td", { class: "small nowrap" }, (r.result && r.result.source) || h("span", { class: "stone ph" }, "—")),
          h("td", null, r.fp_reason ? fpBadge(r.fp_reason) : h("span", { class: "stone ph" }, "—")));
        tbody.appendChild(row);
      }
      replace(tableEl, h("div", { class: "table-wrap" }, h("table", { class: "data refs-table" },
        h("caption", { class: "sr-only" }, `References of ${p.filename}`),
        h("thead", null, h("tr", null, h("th", { class: "num" }, "#"), h("th", null, "Title"), h("th", null, "Verdict"), h("th", null, "Source"), h("th", null, "Safe"))),
        tbody)));
    }

    function truncate(s, n) {
      if (!s) return "";
      return s.length > n ? s.slice(0, n - 1) + "…" : s;
    }

    function selectRef(idx, openIt) {
      rv.selRef = idx;
      tableEl.querySelectorAll("tbody tr").forEach((tr) => {
        const on = Number(tr.dataset.idx) === idx;
        tr.classList.toggle("selected", on);
        tr.setAttribute("aria-selected", String(on));
      });
      if (isNarrow()) {
        if (openIt) openDrawer(); else if (rv.drawer) renderDetailPanel();
      } else {
        renderDetailPanel();
      }
    }

    // ── detail ───────────────────────────────────────────────────────
    function openDrawer() {
      if (!rv.drawer) {
        const prevFocus = document.activeElement;
        const panel = h("aside", { class: "drawer", role: "dialog", "aria-modal": "true", "aria-label": "Reference detail", tabindex: "-1" });
        const backdrop = h("div", { class: "drawer-backdrop", onclick: closeDrawer });
        panel.addEventListener("keydown", (e) => { if (e.key === "Escape") { e.stopPropagation(); closeDrawer(); } });
        $("#overlay-root").append(backdrop, panel);
        rv.drawer = { panel, backdrop, prevFocus };
      }
      renderDetailPanel();
      setTimeout(() => rv.drawer && rv.drawer.panel.focus(), 0);
    }

    function closeDrawer() {
      if (!rv.drawer) return;
      const { panel, backdrop, prevFocus } = rv.drawer;
      panel.remove();
      backdrop.remove();
      rv.drawer = null;
      if (prevFocus && document.contains(prevFocus)) prevFocus.focus();
    }

    function renderDetailPanel() {
      const p = paper();
      const r = selectedRef();
      const targets = [];
      if (!isNarrow() || !rv.drawer) targets.push(detailEl);
      if (rv.drawer) targets.push(rv.drawer.panel);
      for (const target of targets) {
        // Don't clobber an open <select> the user is interacting with.
        if (target.contains(document.activeElement) && document.activeElement.tagName === "SELECT") continue;
        const scroll = target.scrollTop;
        clear(target);
        if (target === rv.drawer?.panel) {
          target.appendChild(h("button", { type: "button", class: "btn-icon drawer-close", "aria-label": "Close detail", onclick: closeDrawer }, "×"));
        }
        if (!p || !r) {
          target.appendChild(h("div", { class: "detail-inner" },
            h("p", { class: "caption" }, "Select a reference to see where it was looked up, what each database answered, and to mark false positives.")));
          continue;
        }
        target.appendChild(refDetail(p, r));
        target.scrollTop = scroll;
      }
    }

    function refDetail(p, r) {
      const res = r.result;
      const inner = h("div", { class: "detail-inner" });
      inner.appendChild(h("div", { class: "row" },
        h("span", { class: "label" }, `Reference [${r.original_number}]`),
        r.origin ? badge(r.origin.toUpperCase(), r.origin === "pdf" ? "badge-outline badge-sm" : "badge-code", r.origin === "pdf" ? "Parsed from the PDF" : `Taken from the ${r.origin} file`) : null,
        verdictBadges(r), r.fp_reason ? fpBadge(r.fp_reason) : null));
      inner.appendChild(h("h2", null, r.title || (res && res.title) || "(no title parsed)"));
      if (r.authors && r.authors.length) inner.appendChild(h("p", { class: "authors-list" }, r.authors.join(", ")));

      // verdict explanation
      const banners = h("div", { class: "stack" });
      if (r.fp_reason) {
        const fp = FP_BY_KEY[r.fp_reason];
        banners.appendChild(h("div", { class: "banner banner-info" }, h("span", null, h("strong", null, "Marked safe: "), fp ? fp.label : r.fp_reason)));
      }
      if (r.retracted && res && res.retraction_info) {
        const ri = res.retraction_info;
        banners.appendChild(h("div", { class: "banner banner-retracted" }, h("span", { class: "break" },
          h("strong", null, "Retracted. "), "This paper has been retracted",
          ri.retraction_source ? ` (${ri.retraction_source})` : "", ".",
          ri.retraction_doi ? [" Notice: ", extLink(doiUrl(ri.retraction_doi), ri.retraction_doi)] : null)));
      }
      if (r.phase === "skipped") {
        banners.appendChild(h("div", { class: "banner banner-info" }, h("span", null, h("strong", null, "Skipped: "), SKIP_LABELS[r.skip_reason] || r.skip_reason || "not checked")));
      } else if (r.phase === "pending") {
        banners.appendChild(h("div", { class: "banner banner-info" }, "Waiting to be checked…"));
      } else if (r.phase === "checking" || r.phase === "retrying") {
        const n = (r.live_dbs || []).length;
        banners.appendChild(h("div", { class: "banner banner-info" }, `${r.phase === "retrying" ? "Re-checking" : "Checking"}… ${n ? plural(n, "database") + " answered so far" : ""}`));
      }
      if (res && (r.phase === "done" || r.phase === "retrying")) {
        switch (r.verdict) {
          case "verified":
            banners.appendChild(h("div", { class: "banner banner-success" }, h("span", null, h("strong", null, "Verified"), res.source ? ` in ${res.source}.` : ".")));
            break;
          case "not_found":
            banners.appendChild(h("div", { class: "banner banner-error" }, h("span", null,
              h("strong", null, "Not found in any checked database — verify by hand. "),
              "This does not prove the reference is fabricated: books, tech reports, very recent or non-English work are often missing.")));
            break;
          case "inconclusive":
            banners.appendChild(h("div", { class: "banner banner-warn" }, h("span", { class: "break" },
              h("strong", null, "Inconclusive. "),
              `No match was found, but ${plural((res.failed_dbs || []).length, "database")} failed to answer`,
              (res.failed_dbs || []).length ? `: ${res.failed_dbs.join(", ")}` : "",
              ". A failed lookup is not evidence of fabrication — try “Re-check”.")));
            break;
          case "mismatch": {
            const kinds = res.mismatch || [];
            const lines = [];
            if (kinds.includes("author")) lines.push(h("li", null, `Authors differ from those listed in ${res.source || "the matching database"}.`));
            if (kinds.includes("doi") && res.doi_info) lines.push(h("li", { class: "break" }, `DOI ${res.doi_info.doi} ${res.doi_info.valid ? "resolves" : "does not resolve to this paper"}`, res.doi_info.title ? ` (resolves to “${res.doi_info.title}”)` : "", "."));
            else if (kinds.includes("doi")) lines.push(h("li", null, "The DOI does not match this paper."));
            if (kinds.includes("arxiv_id") && res.arxiv_info) lines.push(h("li", { class: "break" }, `arXiv ${res.arxiv_info.arxiv_id} ${res.arxiv_info.valid ? "exists" : "does not match this paper"}`, res.arxiv_info.title ? ` (it is “${res.arxiv_info.title}”)` : "", "."));
            else if (kinds.includes("arxiv_id")) lines.push(h("li", null, "The arXiv ID does not match this paper."));
            banners.appendChild(h("div", { class: "banner banner-warn" }, h("div", null,
              h("strong", null, kinds.length ? kinds.map((k) => MISMATCH_LABELS[k] || k).join(" · ") : "Mismatch"),
              lines.length ? h("ul", { style: { margin: "4px 0 0", paddingLeft: "18px" } }, lines) : null)));
            break;
          }
          case "skipped":
            banners.appendChild(h("div", { class: "banner banner-info" }, h("span", null, h("strong", null, "Skipped: "),
              res.url_check_skipped ? "not found in any database, but the reference carries a non-academic URL and URL checking was disabled for this run." : "not checked.")));
            break;
          default: break;
        }
      }
      if (banners.childNodes.length) inner.appendChild(banners);

      // actions
      const fpSel = h("select", { class: "input input-sm", "aria-label": "Mark as safe" },
        h("option", { value: "", selected: !r.fp_reason }, "Not marked"),
        FP_REASONS.map((f) => h("option", { value: f.key, selected: r.fp_reason === f.key }, `Safe — ${f.label}`)));
      fpSel.addEventListener("change", () => setFp(p, r, fpSel.value || null, fpSel));
      const recheck = h("button", { type: "button", class: "btn btn-tertiary btn-sm", disabled: r.phase === "skipped" || r.phase === "checking" || r.phase === "retrying", onclick: () => retryPaper("ref", r.idx) }, "Re-check this reference");
      inner.appendChild(h("div", { class: "detail-section" },
        h("h3", null, "Review"),
        h("label", { class: "field" }, h("span", { class: "sr-only" }, "Mark as safe"), fpSel),
        h("div", null, recheck)));

      // identifiers & match
      const kv = h("dl", { class: "kv" });
      const addKv = (k, ...v) => { kv.appendChild(h("dt", null, k)); kv.appendChild(h("dd", null, v)); };
      if (res && res.source) addKv("Matched in", res.source, res.paper_url ? [" · ", extLink(res.paper_url, "open record")] : null);
      else if (res && res.paper_url) addKv("Record", extLink(res.paper_url));
      if (r.doi) {
        const di = res && res.doi_info;
        addKv("DOI", extLink(doiUrl(r.doi), r.doi), di ? [" ", badge(di.valid ? "resolves" : "invalid", di.valid ? "badge-success badge-sm" : "badge-error badge-sm")] : null);
      }
      if (r.arxiv_id) {
        const ai = res && res.arxiv_info;
        addKv("arXiv", extLink(arxivUrl(r.arxiv_id), r.arxiv_id), ai ? [" ", badge(ai.valid ? "valid" : "invalid", ai.valid ? "badge-success badge-sm" : "badge-error badge-sm")] : null);
      }
      if (r.urls && r.urls.length) addKv("URLs", h("div", { class: "stack", style: { gap: "2px" } }, r.urls.map((u) => extLink(u))));
      if (kv.childNodes.length) inner.appendChild(h("div", { class: "detail-section" }, h("h3", null, "Identifiers"), kv));

      // authors comparison
      if (res && res.found_authors && res.found_authors.length) {
        inner.appendChild(h("div", { class: "detail-section" },
          h("h3", null, "Authors"),
          h("dl", { class: "kv" },
            h("dt", null, "In citation"), h("dd", null, (res.ref_authors && res.ref_authors.length ? res.ref_authors : r.authors || []).join(", ") || "—"),
            h("dt", null, `In ${res.source || "database"}`), h("dd", null, res.found_authors.join(", ")))));
      }

      // raw citation
      if (r.raw_citation) inner.appendChild(h("div", { class: "detail-section" }, h("h3", null, "Raw citation"), h("div", { class: "raw-block" }, r.raw_citation)));

      // per-database table
      const rows = res && res.db_results && res.db_results.length && r.phase !== "retrying"
        ? res.db_results.map((d) => ({ db: d.db, status: d.status, elapsed_ms: d.elapsed_ms, error: d.error, url: d.paper_url }))
        : (r.live_dbs || []).map((d) => ({ db: d.db, status: d.status, elapsed_ms: d.elapsed_ms }));
      if (rows.length) {
        const order = { match: 0, author_mismatch: 1, no_match: 2, timeout: 3, rate_limited: 3, error: 3, skipped: 4 };
        rows.sort((a, b) => (order[a.status] ?? 5) - (order[b.status] ?? 5) || String(a.db).localeCompare(String(b.db)));
        inner.appendChild(h("div", { class: "detail-section" },
          h("h3", null, "Databases"),
          h("div", { class: "table-wrap" }, h("table", { class: "data compact" },
            h("thead", null, h("tr", null, h("th", null, "Database"), h("th", null, "Result"), h("th", { class: "num" }, "Time"))),
            h("tbody", null, rows.map((d) => h("tr", null,
              h("td", null, d.url ? extLink(d.url, d.db) : d.db, d.error ? h("div", { class: "t-sub" }, d.error) : null),
              h("td", null, h("span", { class: "chip chip-" + d.status }, DB_STATUS_LABELS[d.status] || d.status)),
              h("td", { class: "num stone nowrap" }, d.elapsed_ms != null ? `${fmtNum(d.elapsed_ms)} ms` : "—")))))),
          res && res.failed_dbs && res.failed_dbs.length ? h("p", { class: "caption" }, `Still failing after retries: ${res.failed_dbs.join(", ")}`) : null));
      }
      return inner;
    }

    async function setFp(p, r, reason, sel) {
      if (sel) sel.disabled = true;
      try {
        const res = await api("PUT", `${base}/papers/${p.idx}/refs/${r.idx}/fp`, { reason });
        if (res && res.ref) upsertRef(p, res.ref);
        else r.fp_reason = reason;
        if (res && res.stats) p.stats = res.stats;
        toast(reason ? `Marked safe: ${FP_BY_KEY[reason].label}` : "Mark removed.", "success", 2500);
        if (sel) sel.disabled = false;
        if (sel) sel.blur();
        schedule("stats", "papers", "table", "detail");
        flush();
      } catch (e) {
        if (sel) sel.disabled = false;
        showError(e);
      }
    }

    // ── keyboard ─────────────────────────────────────────────────────
    function onKey(e) {
      if (!ctx.alive() || e.metaKey || e.ctrlKey || e.altKey) return;
      if (overlayStack.length) return;
      if (isTypingTarget(e.target)) return;
      const refs = visibleRefs();
      if (e.key === "Escape" && rv.drawer) { closeDrawer(); return; }
      if (!refs.length) return;
      const pos = refs.findIndex((r) => r.idx === rv.selRef);
      if (e.key === "j" || e.key === "k") {
        const next = e.key === "j" ? Math.min(refs.length - 1, pos + 1) : Math.max(0, pos < 0 ? 0 : pos - 1);
        selectRef(refs[next].idx, false);
        const tr = tableEl.querySelector(`tr[data-idx="${refs[next].idx}"]`);
        if (tr) { tr.focus({ preventScroll: true }); tr.scrollIntoView({ block: "nearest" }); }
        e.preventDefault();
      } else if (e.key === "Enter" && pos >= 0 && !(e.target && e.target.closest && e.target.closest("tr"))) {
        selectRef(refs[pos].idx, true);
      } else if (e.key === "s" && pos >= 0) {
        const r = refs[pos];
        const order = [null, ...FP_REASONS.map((f) => f.key)];
        const next = order[(order.indexOf(r.fp_reason || null) + 1) % order.length];
        setFp(paper(), r, next, null);
        e.preventDefault();
      }
    }
    document.addEventListener("keydown", onKey);

    // Re-render the detail panel when crossing the drawer breakpoint.
    const mq = window.matchMedia("(max-width: 1023px)");
    const onMq = () => { if (!mq.matches) closeDrawer(); schedule("detail"); };
    mq.addEventListener("change", onMq);
    ctx.on(() => mq.removeEventListener("change", onMq));

    connect();
  }

  // ════════════════════════════════════════════════════════════════════
  // 5c. View: History
  // ════════════════════════════════════════════════════════════════════

  const historyState = { q: "", status: "", all: false, offset: 0 };
  const HISTORY_LIMIT = 50;

  function viewHistory(root, ctx) {
    const isAdmin = S.user.role === "admin";
    const listEl = h("div", null, skeleton(4));
    const pagerEl = h("div", { class: "row-between mt-md" });
    const search = h("input", { class: "search-pill", type: "search", placeholder: "Search by title or file name…", "aria-label": "Search runs", value: historyState.q });
    search.style.flex = "1 1 240px";
    search.addEventListener("input", debounce(() => { historyState.q = search.value; historyState.offset = 0; load(); }, 300));
    const statuses = [["", "All"], ["running", "Running"], ["done", "Done"], ["failed", "Failed"], ["cancelled", "Cancelled"], ["interrupted", "Interrupted"], ["queued", "Queued"]];
    const pills = h("div", { class: "pill-tabs pill-tabs-sm", role: "toolbar", "aria-label": "Filter by status" },
      statuses.map(([v, l]) => h("button", {
        type: "button", class: "pill-tab", "aria-pressed": String(historyState.status === v), dataset: { v },
        onclick: () => {
          historyState.status = v;
          historyState.offset = 0;
          pills.querySelectorAll(".pill-tab").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.v === v)));
          load();
        },
      }, l)));
    const allSw = isAdmin ? switchEl("All users", { checked: historyState.all, onchange: (e) => { historyState.all = e.target.checked; historyState.offset = 0; load(); } }) : null;

    root.appendChild(h("div", { class: "container page" },
      h("div", { class: "page-head" },
        h("div", null, h("h1", { class: "heading-lg" }, "History"), h("p", { class: "muted" }, "Every check you have run, with its results kept for review.")),
        h("a", { class: "btn btn-primary", href: "#/" }, "New check")),
      h("div", { class: "toolbar" }, search, allSw ? allSw.el : null),
      h("div", { class: "toolbar" }, pills),
      listEl, pagerEl));

    async function load() {
      const params = new URLSearchParams({ limit: String(HISTORY_LIMIT), offset: String(historyState.offset) });
      if (historyState.q.trim()) params.set("q", historyState.q.trim());
      if (historyState.status) params.set("status", historyState.status);
      if (isAdmin && historyState.all) params.set("all", "1");
      const token = ++load.token;
      try {
        const data = await api("GET", "/api/runs?" + params.toString());
        if (!ctx.alive() || token !== load.token) return;
        const runs = (data && data.runs) || [];
        const total = (data && data.total) || 0;
        if (!runs.length) {
          replace(listEl, emptyState(historyState.q || historyState.status ? "No matching runs" : "No runs yet",
            historyState.q || historyState.status ? "Try a different search or filter." : "Start a check and it will appear here.",
            historyState.q || historyState.status ? null : h("a", { class: "btn btn-primary", href: "#/" }, "New check")));
        } else {
          replace(listEl, runsTable(runs, isAdmin && historyState.all));
        }
        clear(pagerEl);
        if (total > 0) {
          const from = historyState.offset + 1;
          const to = Math.min(total, historyState.offset + runs.length);
          append(pagerEl,
            h("span", { class: "caption" }, `Showing ${fmtNum(from)}–${fmtNum(to)} of ${fmtNum(total)}`),
            h("div", { class: "btn-group" },
              h("button", { type: "button", class: "btn btn-tertiary btn-sm", disabled: historyState.offset === 0, onclick: () => { historyState.offset = Math.max(0, historyState.offset - HISTORY_LIMIT); load(); } }, "← Previous"),
              h("button", { type: "button", class: "btn btn-tertiary btn-sm", disabled: to >= total, onclick: () => { historyState.offset += HISTORY_LIMIT; load(); } }, "Next →")));
        }
      } catch (e) {
        if (!ctx.alive()) return;
        replace(listEl, h("p", { class: "field-error" }, e.message));
      }
    }
    load.token = 0;
    load();
  }

  // ════════════════════════════════════════════════════════════════════
  // 5d. View: Databases
  // ════════════════════════════════════════════════════════════════════

  const SOURCE_TAG_RE = /^[A-Za-z0-9_.:-]{1,64}$/;

  function viewDatabases(root, ctx) {
    const isAdmin = S.user.role === "admin";
    const headInfo = h("div", { class: "row" });
    const cardsEl = h("div", { class: "db-cards" }, skeleton(2), skeleton(2));
    const cacheEl = h("div");
    const jobsEl = h("div", null, skeleton(2));
    let pollTimer = null;

    root.appendChild(h("div", { class: "container page" },
      h("div", { class: "page-head" },
        h("div", null,
          h("h1", { class: "heading-lg" }, "Reference databases"),
          h("p", { class: "muted" }, "Offline indexes the checker queries locally, how fresh they are, and updates to the latest snapshot."),
          h("div", { class: "mt-sm" }, headInfo)),
        h("button", { type: "button", class: "btn btn-tertiary btn-sm", onclick: () => load() }, "Refresh")),
      cardsEl,
      h("section", { class: "section" }, h("h2", { class: "section-title" }, "Query cache"), cacheEl),
      h("section", { class: "section" }, h("h2", { class: "section-title" }, "Recent jobs"), jobsEl)));

    ctx.on(() => clearTimeout(pollTimer));

    async function load() {
      clearTimeout(pollTimer);
      try {
        const [data, jobs] = await Promise.all([api("GET", "/api/databases"), api("GET", "/api/jobs?limit=20")]);
        if (!ctx.alive()) return;
        renderHead(data);
        renderCards(data);
        renderCache(data);
        renderJobs((jobs && jobs.jobs) || []);
        const anyActive = (data.databases || []).some((d) => d.active_job) || ((jobs && jobs.jobs) || []).some((j) => j.status === "running");
        if (anyActive) pollTimer = setTimeout(load, 10000);
      } catch (e) {
        if (!ctx.alive()) return;
        replace(cardsEl, h("p", { class: "field-error" }, e.message));
      }
    }

    function renderHead(data) {
      replace(headInfo,
        data.cli_available
          ? badge(`hallucinator-cli ${data.cli_version || ""}`.trim(), "badge-success", data.cli_path || "")
          : badge("hallucinator-cli not found — updates unavailable", "badge-error", data.cli_path || ""),
        isAdmin && data.cli_path ? h("code", { class: "small" }, data.cli_path) : null,
        !isAdmin ? null
          : data.config_path ? h("span", { class: "caption" }, "Config: ", h("code", null, data.config_path))
          : h("span", { class: "caption" }, "No config file — using defaults and auto-detected paths"));
    }

    function dbStatusBadge(d) {
      if (d.active_job) return pulseBadge("Updating");
      if (!d.exists) return badge("Missing", "badge-muted");
      if (!d.loaded) return badge("Not loaded", "badge-warn", d.load_error || "");
      if (d.stale) return badge("Stale", "badge-warn");
      return badge("Ready", "badge-success");
    }

    function renderCards(data) {
      clear(cardsEl);
      const dbs = data.databases || [];
      if (!dbs.length) { cardsEl.appendChild(emptyState("No databases", "The server did not report any offline databases.")); return; }
      for (const d of dbs) cardsEl.appendChild(dbCard(d, data));
    }

    function dbCard(d, data) {
      const isCorpus = d.key === "corpus";
      const card = h("article", { class: "card db-card" + (isCorpus ? " span-2" : ""), "aria-labelledby": `db-${d.key}` });
      const actions = h("div", { class: "btn-group" });
      if (isAdmin && d.active_job) actions.appendChild(h("button", { type: "button", class: "btn btn-secondary btn-sm", onclick: () => openJobLog(d.active_job.id, load) }, "View live log"));
      if (isAdmin && d.update && d.update.supported && !d.active_job && d.update.action !== "import") {
        actions.appendChild(h("button", {
          type: "button", class: "btn btn-primary btn-sm", disabled: !data.cli_available,
          title: data.cli_available ? null : "hallucinator-cli is not available on the server",
          onclick: () => startUpdate(d),
        }, d.exists ? "Update now" : "Build now"));
      }
      card.appendChild(h("div", { class: "card-head" },
        h("div", { class: "grow" },
          h("div", { class: "row" }, h("h3", { class: "card-title", id: `db-${d.key}` }, d.label), dbStatusBadge(d)),
          d.description ? h("p", { class: "caption" }, d.description) : null),
        actions));
      if (isAdmin) card.appendChild(h("div", { class: "row" },
        h("span", { class: "db-path grow" }, d.path || "(no path)"),
        d.path_source ? badge(d.path_source, "badge-outline badge-sm", { env: "From an environment variable", config: "From the config file", auto: "Auto-detected", default: "Default location (not built yet)" }[d.path_source] || "") : null));
      const meta = h("div", { class: "meta-grid" });
      const addMeta = (label, val, title) => meta.appendChild(h("div", { title: title || null }, h("div", { class: "m-label" }, label), h("div", { class: "m-val" }, val)));
      addMeta("Size", d.exists ? fmtBytes(d.size_bytes) : "—");
      addMeta("Built", d.build_date ? [fmtDate(d.build_date), d.age_days != null ? h("span", { class: d.stale ? "" : "stone" }, ` · ${plural(d.age_days, "day")} old`) : null] : (d.age_days != null ? `${plural(d.age_days, "day")} old` : "—"), d.build_date || "");
      addMeta("Modified", d.modified_at ? timeEl(d.modified_at) : "—");
      for (const rec of d.records || []) addMeta(rec.label, fmtNum(rec.count));
      card.appendChild(meta);
      if (d.load_error) card.appendChild(h("div", { class: "banner banner-warn" }, h("span", { class: "break" }, d.load_error)));
      if (d.stale && d.exists) card.appendChild(h("p", { class: "caption" }, "This snapshot is older than 30 days; recently published papers may be missing."));
      if (isAdmin && d.update && d.update.notes) card.appendChild(h("p", { class: "caption" }, d.update.notes));
      const lj = d.last_job;
      if (lj && (!d.active_job || d.active_job.id !== lj.id)) {
        card.appendChild(h("div", { class: "row caption" },
          h("span", null, "Last job:"), jobStatusBadge(lj.status), timeEl(lj.finished_at || lj.created_at),
          isAdmin ? h("button", { type: "button", class: "btn-link", onclick: () => openJobLog(lj.id, load) }, "View log") : null));
      }
      if (isCorpus) appendCorpusExtras(card, d, data);
      return card;
    }

    function appendCorpusExtras(card, d, data) {
      const sources = d.sources || [];
      if (sources.length) {
        const sorted = sources.slice().sort((a, b) => String(a.source).localeCompare(String(b.source)));
        card.appendChild(h("details", null,
          h("summary", { class: "label", style: { cursor: "pointer" } }, `${plural(sources.length, "source")} in the corpus`),
          h("div", { class: "table-wrap mt-sm", style: { maxHeight: "320px", overflowY: "auto" } }, h("table", { class: "data compact" },
            h("thead", null, h("tr", null, h("th", null, "Source tag"), h("th", { class: "num" }, "Records"))),
            h("tbody", null, sorted.map((s) => h("tr", null, h("td", null, h("code", null, s.source)), h("td", { class: "num" }, fmtNum(s.count)))))))));
      } else if (d.exists) {
        card.appendChild(h("p", { class: "caption" }, "The corpus is empty."));
      }
      if (!isAdmin) return;
      const venues = data.venues || [];
      const ms = data.marked_safe_count || 0;
      const disabled = !data.cli_available || !!d.active_job;

      const venueSel = h("select", { class: "input", "aria-label": "Venue" },
        venues.map((v) => h("option", { value: v.key, title: v.about || "" }, `${v.key}${v.about ? " — " + truncateText(v.about, 70) : ""}`)));
      const urlIn = h("input", { class: "input", type: "url", placeholder: "https://…", autocomplete: "off" });
      const pathIn = h("input", { class: "input mono", placeholder: "/path/on/server/proceedings.pdf", autocomplete: "off" });
      const tagIn = h("input", { class: "input", placeholder: "e.g. usenix2026", autocomplete: "off", maxlength: "64" });
      const urlField = h("label", { class: "field" }, h("span", null, "Proceedings / program page URL"), urlIn);
      const pathField = h("label", { class: "field hidden" }, h("span", null, "PDF path on the server"), pathIn);
      const aboutEl = h("p", { class: "caption" });
      const errEl = h("p", { class: "field-error hidden", role: "alert" });
      const curVenue = () => venues.find((v) => v.key === venueSel.value);
      const syncVenue = () => {
        const v = curVenue();
        const isPdf = v && v.input === "pdf";
        urlField.classList.toggle("hidden", !!isPdf);
        pathField.classList.toggle("hidden", !isPdf);
        tagIn.placeholder = v ? `e.g. ${v.key.replace(/[^a-z0-9]/gi, "")}${new Date().getFullYear()}` : "e.g. usenix2026";
        aboutEl.textContent = v && v.about ? v.about : "";
      };
      venueSel.addEventListener("change", syncVenue);
      syncVenue();
      const submit = h("button", { type: "submit", class: "btn btn-primary btn-sm", disabled: disabled || !venues.length }, "Import");
      const form = h("form", {
        class: "stack", novalidate: true,
        onsubmit: async (e) => {
          e.preventDefault();
          errEl.classList.add("hidden");
          const v = curVenue();
          const tag = tagIn.value.trim();
          const body = { venue: v ? v.key : "", source_tag: tag };
          let msg = null;
          if (!v) msg = "Choose a venue.";
          else if (!SOURCE_TAG_RE.test(tag)) msg = "Source tag must be 1–64 characters: letters, digits, _ . : -";
          else if (v.input === "pdf") {
            if (!pathIn.value.trim()) msg = "Enter the PDF path on the server.";
            body.pdf_path = pathIn.value.trim();
          } else {
            if (!isHttpUrl(urlIn.value)) msg = "Enter an http(s) URL.";
            body.url = urlIn.value.trim();
          }
          if (msg) { errEl.textContent = msg; errEl.classList.remove("hidden"); return; }
          submit.disabled = true;
          try {
            const res = await api("POST", "/api/databases/corpus/import", body);
            toast("Import started.", "success");
            if (res && res.job) openJobLog(res.job.id, load);
            load();
          } catch (err) {
            errEl.textContent = err.message;
            errEl.classList.remove("hidden");
            submit.disabled = false;
          }
        },
      },
        h("div", { class: "form-grid" },
          h("label", { class: "field" }, h("span", null, "Venue"), venueSel),
          h("label", { class: "field" }, h("span", null, "Source tag"), tagIn)),
        aboutEl, urlField, pathField, errEl, h("div", null, submit));

      const msBtn = h("button", {
        type: "button", class: "btn btn-secondary btn-sm", disabled: disabled || !ms,
        onclick: async () => {
          const ok = await confirmDialog({ title: "Import marked-safe references?", message: `${plural(ms, "reference")} marked safe across the run history will be added to the local corpus, so differently-worded citations of the same papers verify automatically.`, confirmLabel: "Import" });
          if (!ok) return;
          msBtn.disabled = true;
          try {
            const res = await api("POST", "/api/databases/corpus/import-marked-safe");
            toast("Import started.", "success");
            if (res && res.job) openJobLog(res.job.id, load);
            load();
          } catch (err) { showError(err); msBtn.disabled = false; }
        },
      }, ms ? `Import ${plural(ms, "marked-safe reference")}` : "No marked-safe references yet");

      card.appendChild(h("div", { class: "detail-section" },
        h("h3", null, "Grow the corpus"),
        h("p", { class: "caption" }, "Scrape a recent conference's accepted-papers page into the corpus (re-running is safe — duplicates are skipped), or fold in references reviewers marked safe."),
        venues.length ? form : h("p", { class: "caption" }, "No venue importers were reported by hallucinator-cli."),
        h("div", { class: "row" }, msBtn)));
    }

    function truncateText(s, n) { return s && s.length > n ? s.slice(0, n - 1) + "…" : s; }

    async function startUpdate(d) {
      const params = (d.update && d.update.params) || [];
      const values = {};
      const inputs = {};
      const errEl = h("p", { class: "field-error hidden", role: "alert" });
      const fields = params.map((p) => {
        let input;
        if (p.kind === "bool") {
          input = h("input", { type: "checkbox" });
          inputs[p.name] = input;
          return h("label", { class: "check" }, input, p.label || p.name);
        }
        input = h("input", {
          class: "input" + (p.kind === "path" ? " mono" : ""),
          type: p.kind === "number" ? "number" : (p.kind === "date" ? "date" : "text"),
          placeholder: p.placeholder || (p.kind === "path" ? "/path/on/server" : ""),
          required: !!p.required,
        });
        inputs[p.name] = input;
        return h("label", { class: "field" }, h("span", null, p.label || p.name, p.required ? "" : h("span", { class: "stone" }, " (optional)")), input,
          p.help ? h("small", { class: "field-hint" }, p.help) : null);
      });
      const go = h("button", { type: "button", class: "btn btn-primary" }, d.exists ? "Start update" : "Start build");
      const cancel = h("button", { type: "button", class: "btn btn-tertiary", onclick: () => m.close() }, "Cancel");
      const m = openModal({
        title: `${d.exists ? "Update" : "Build"} ${d.label}`,
        body: [
          h("p", { class: "muted small" }, `Runs hallucinator-cli on the server and writes to `, h("code", null, d.path || "the default path"), "."),
          d.update && d.update.notes ? h("div", { class: "banner banner-info" }, d.update.notes) : null,
          fields, errEl,
        ],
        actions: [cancel, go],
      });
      go.addEventListener("click", async () => {
        errEl.classList.add("hidden");
        for (const p of params) {
          const inp = inputs[p.name];
          if (p.kind === "bool") { if (inp.checked) values[p.name] = true; continue; }
          const v = inp.value.trim();
          if (p.required && !v) { errEl.textContent = `${p.label || p.name} is required.`; errEl.classList.remove("hidden"); inp.focus(); return; }
          if (v) values[p.name] = p.kind === "number" ? Number(v) : v;
        }
        go.disabled = true;
        try {
          const res = await api("POST", `/api/databases/${encodeURIComponent(d.key)}/update`, { params: values });
          m.close();
          toast(`${d.label}: update started.`, "success");
          if (res && res.job) openJobLog(res.job.id, load);
          load();
        } catch (e) {
          go.disabled = false;
          errEl.textContent = e.message;
          errEl.classList.remove("hidden");
        }
      });
    }

    function renderCache(data) {
      const c = data.cache;
      if (!c) { replace(cacheEl, h("p", { class: "caption" }, "No query cache information.")); return; }
      const clearBtn = (label, notFoundOnly) => h("button", {
        type: "button", class: notFoundOnly ? "btn btn-tertiary btn-sm" : "btn btn-secondary btn-sm", disabled: !c.exists,
        onclick: async () => {
          const ok = await confirmDialog({
            title: notFoundOnly ? "Clear not-found entries?" : "Clear the whole query cache?",
            message: notFoundOnly ? "Cached “not found” answers will be dropped so those references are looked up again next time." : "Every cached database answer will be dropped. The next checks will be slower while the cache refills.",
            confirmLabel: "Clear", danger: !notFoundOnly,
          });
          if (!ok) return;
          try {
            const res = await api("POST", "/api/databases/cache/clear", { not_found_only: notFoundOnly });
            toast(res && res.removed != null ? `Removed ${plural(res.removed, "entry", "entries")}.` : "Cache cleared.", "success");
            load();
          } catch (e) { showError(e); }
        },
      }, label);
      replace(cacheEl, h("div", { class: "card" },
        h("div", { class: "card-head" },
          h("div", { class: "grow stack", style: { gap: "6px" } },
            h("div", { class: "row" }, h("span", { class: "card-title" }, "Persistent query cache"), c.exists ? badge("Active", "badge-success") : badge("Not created yet", "badge-muted")),
            isAdmin ? h("span", { class: "db-path" }, c.path || "(in memory)") : null,
            h("span", { class: "caption" }, `${c.exists ? fmtBytes(c.size_bytes) : "—"}${c.entries != null ? ` · ${plural(c.entries, "entry", "entries")}` : ""} · avoids re-querying the same reference across runs`)),
          isAdmin ? h("div", { class: "btn-group" }, clearBtn("Clear not-found", true), clearBtn("Clear all", false)) : null)));
    }

    function renderJobs(jobs) {
      if (!jobs.length) { replace(jobsEl, emptyState("No jobs yet", "Database updates and corpus imports will be listed here.")); return; }
      replace(jobsEl, h("div", { class: "table-wrap" }, h("table", { class: "data" },
        h("thead", null, h("tr", null, h("th", null, "Job"), h("th", null, "Status"), h("th", null, "Started"), h("th", null, "Duration"), h("th", { class: "num" }, "Exit"), h("th", null, "User"), isAdmin ? h("th", null, "") : null)),
        h("tbody", null, jobs.map((j) => h("tr", null,
          h("td", null, h("div", { class: "t-title" }, j.label || j.db_key), j.argv && j.argv.length ? h("div", { class: "t-sub mono" }, truncateText(j.argv.join(" "), 90)) : null),
          h("td", null, jobStatusBadge(j.status)),
          h("td", { class: "nowrap" }, timeEl(j.created_at)),
          h("td", { class: "nowrap" }, j.finished_at ? fmtDuration(j.finished_at - j.created_at) : (j.status === "running" ? fmtDuration(nowSec() - j.created_at) : "—")),
          h("td", { class: "num" }, j.exit_code != null ? String(j.exit_code) : "—"),
          h("td", null, j.username || "—"),
          isAdmin ? h("td", null, h("button", { type: "button", class: "btn btn-tertiary btn-xs", onclick: () => openJobLog(j.id, load) }, "Log")) : null))))));
    }

    load();
  }

  /** Live job log modal (SSE /api/jobs/:id/events, falling back to GET). */
  function openJobLog(jobId, onFinished) {
    const isAdmin = S.user && S.user.role === "admin";
    const pane = h("pre", { class: "log-pane", tabindex: "0", "aria-label": "Job log", "aria-live": "off" });
    const statusEl = h("span");
    const argvEl = h("code", { class: "small break" });
    const cancelBtn = h("button", { type: "button", class: "btn btn-danger btn-sm hidden" }, "Cancel job");
    const autoSw = switchEl("Auto-scroll", { checked: true });
    let es = null;
    let job = null;
    let finished = false;
    let needsNl = false;
    const m = openModal({
      title: "Job log",
      wide: true,
      body: [h("div", { class: "row-between" }, h("div", { class: "row" }, statusEl, argvEl), h("div", { class: "row" }, autoSw.el, isAdmin ? cancelBtn : null)), pane],
      actions: [h("button", { type: "button", class: "btn btn-tertiary", onclick: () => m.close() }, "Close")],
      onClose: () => { if (es) es.close(); if (finished && onFinished) onFinished(); },
    });
    const titleEl = $("h2", m.el);

    const scroll = () => { if (autoSw.input.checked) pane.scrollTop = pane.scrollHeight; };
    function setJob(j) {
      job = j;
      if (titleEl) titleEl.textContent = j.label || "Job log";
      replace(statusEl, jobStatusBadge(j.status));
      argvEl.textContent = j.argv ? "hallucinator-cli " + j.argv.join(" ") : "";
      cancelBtn.classList.toggle("hidden", j.status !== "running");
      if (j.status !== "running") finished = true;
    }
    cancelBtn.addEventListener("click", async () => {
      const ok = await confirmDialog({ title: "Cancel this job?", message: "The hallucinator-cli process will be stopped. A partially built database is not swapped in.", confirmLabel: "Cancel job", danger: true });
      if (!ok) return;
      try { await api("POST", `/api/jobs/${encodeURIComponent(jobId)}/cancel`); toast("Cancelling job…"); }
      catch (e) { showError(e); }
    });

    function fallback() {
      api("GET", `/api/jobs/${encodeURIComponent(jobId)}`).then((d) => {
        if (!d) return;
        setJob(d.job);
        pane.textContent = d.log || "";
        needsNl = !!d.log && !d.log.endsWith("\n");
        scroll();
      }).catch(showError);
    }

    es = new EventSource(`/api/jobs/${encodeURIComponent(jobId)}/events`);
    let gotSnapshot = false;
    es.addEventListener("snapshot", (ev) => {
      try {
        const d = JSON.parse(ev.data);
        gotSnapshot = true;
        setJob(d.job);
        pane.textContent = d.log || "";
        needsNl = !!d.log && !d.log.endsWith("\n");
        scroll();
      } catch (_) { /* ignore */ }
    });
    es.addEventListener("line", (ev) => {
      try {
        const d = JSON.parse(ev.data);
        pane.appendChild(document.createTextNode((needsNl ? "\n" : "") + d.line));
        needsNl = true;
        scroll();
      } catch (_) { /* ignore */ }
    });
    es.addEventListener("status", (ev) => {
      try { setJob(JSON.parse(ev.data).job); } catch (_) { /* ignore */ }
    });
    es.addEventListener("end", () => { es.close(); finished = true; });
    es.onerror = () => {
      es.close();
      if (!gotSnapshot || (job && job.status === "running")) fallback();
    };
  }

  // ════════════════════════════════════════════════════════════════════
  // 5e. View: Admin
  // ════════════════════════════════════════════════════════════════════

  function viewAdmin(root, ctx) {
    if (S.user.role !== "admin") {
      root.appendChild(h("div", { class: "container page" }, emptyState("Administrators only", "You need an administrator account to manage users.", h("a", { class: "btn btn-primary", href: "#/" }, "New check"))));
      return;
    }
    const usersEl = h("div", null, skeleton(3));
    const eventsEl = h("div", null, skeleton(3));
    const blockedEl = h("div");

    const uIn = h("input", { class: "input", autocomplete: "off", autocapitalize: "off", spellcheck: "false", maxlength: "32", placeholder: "username" });
    const pIn = h("input", { class: "input", type: "password", autocomplete: "new-password", placeholder: "at least 10 characters" });
    const roleSel = h("select", { class: "input" }, h("option", { value: "user" }, "User"), h("option", { value: "admin" }, "Administrator"));
    const cErr = h("p", { class: "field-error hidden", role: "alert" });
    const createForm = h("form", {
      class: "card stack", novalidate: true,
      onsubmit: async (e) => {
        e.preventDefault();
        cErr.classList.add("hidden");
        const username = uIn.value.trim();
        const password = pIn.value;
        let msg = null;
        if (!/^[A-Za-z0-9_.-]{3,32}$/.test(username)) msg = "Username must be 3–32 characters: letters, digits, _ . -";
        else if (password.length < 10 || password.length > 256) msg = "Password must be between 10 and 256 characters.";
        if (msg) { cErr.textContent = msg; cErr.classList.remove("hidden"); return; }
        try {
          await api("POST", "/api/admin/users", { username, password, role: roleSel.value });
          toast(`User ${username} created.`, "success");
          createForm.reset();
          loadUsers();
        } catch (err) { cErr.textContent = err.message; cErr.classList.remove("hidden"); }
      },
    },
      h("h3", { class: "card-title" }, "Create user"),
      h("div", { class: "form-grid" },
        h("label", { class: "field" }, h("span", null, "Username"), uIn),
        h("label", { class: "field" }, h("span", null, "Role"), roleSel)),
      h("label", { class: "field" }, h("span", null, "Initial password"), pIn),
      cErr,
      h("div", null, h("button", { type: "submit", class: "btn btn-primary btn-sm" }, "Create user")));

    root.appendChild(h("div", { class: "container page" },
      h("div", { class: "page-head" },
        h("div", null, h("h1", { class: "heading-lg" }, "Admin"), h("p", { class: "muted" }, "Accounts and sign-in security. Only administrators can create accounts."))),
      h("section", null, h("div", { class: "section-head" }, h("h2", { class: "section-title" }, "Users"), h("button", { type: "button", class: "btn btn-tertiary btn-sm", onclick: () => loadUsers() }, "Refresh")), usersEl),
      h("section", { class: "section" }, createForm),
      h("section", { class: "section" },
        h("div", { class: "section-head" }, h("h2", { class: "section-title" }, "Sign-in activity"), h("button", { type: "button", class: "btn btn-tertiary btn-sm", onclick: () => loadEvents() }, "Refresh")),
        blockedEl, eventsEl)));

    async function patchUser(u, body, okMsg) {
      try {
        await api("PATCH", `/api/admin/users/${u.id}`, body);
        toast(okMsg, "success");
        loadUsers();
      } catch (e) { showError(e); }
    }

    async function loadUsers() {
      try {
        const data = await api("GET", "/api/admin/users");
        if (!ctx.alive()) return;
        const users = (data && data.users) || [];
        const now = nowSec();
        const rows = users.map((u) => {
          const self = u.id === S.user.id;
          const locked = u.locked_until && u.locked_until > now;
          const acts = h("div", { class: "btn-group" });
          if (u.status === "pending") acts.appendChild(h("button", { type: "button", class: "btn btn-primary btn-xs", onclick: () => patchUser(u, { status: "active" }, `${u.username} approved.`) }, "Approve"));
          if (!self && u.status === "active") acts.appendChild(h("button", { type: "button", class: "btn btn-tertiary btn-xs", onclick: () => patchUser(u, { status: "disabled" }, `${u.username} disabled.`) }, "Disable"));
          if (!self && u.status === "disabled") acts.appendChild(h("button", { type: "button", class: "btn btn-tertiary btn-xs", onclick: () => patchUser(u, { status: "active" }, `${u.username} enabled.`) }, "Enable"));
          if (!self) acts.appendChild(h("button", { type: "button", class: "btn btn-tertiary btn-xs", onclick: () => patchUser(u, { role: u.role === "admin" ? "user" : "admin" }, `${u.username} is now ${u.role === "admin" ? "a user" : "an administrator"}.`) }, u.role === "admin" ? "Make user" : "Make admin"));
          if (locked || u.failed_streak) acts.appendChild(h("button", { type: "button", class: "btn btn-secondary btn-xs", onclick: () => patchUser(u, { unlock: true }, `${u.username} unlocked.`) }, "Unlock"));
          if (!self) acts.appendChild(h("button", {
            type: "button", class: "btn btn-tertiary btn-xs",
            onclick: async () => {
              const ok = await confirmDialog({ title: `Delete ${u.username}?`, message: `The account and its ${plural(u.run_count || 0, "run")} will be permanently deleted.`, confirmLabel: "Delete user", danger: true });
              if (!ok) return;
              try { await api("DELETE", `/api/admin/users/${u.id}`); toast(`${u.username} deleted.`, "success"); loadUsers(); }
              catch (e) { showError(e); }
            },
          }, "Delete"));
          const statusB = u.status === "active" ? badge("Active", "badge-success badge-sm") : u.status === "pending" ? badge("Pending approval", "badge-warn badge-sm") : badge("Disabled", "badge-muted badge-sm");
          return h("tr", null,
            h("td", null, h("div", { class: "row" }, h("span", { class: "t-title" }, u.username), self ? badge("you", "badge-outline badge-sm") : null)),
            h("td", null, u.role === "admin" ? badge("Admin", "badge-dark badge-sm") : badge("User", "badge-outline badge-sm")),
            h("td", null, h("div", { class: "row" }, statusB, locked ? badge(`Locked until ${new Date(u.locked_until * 1000).toLocaleTimeString()}`, "badge-error badge-sm", absTime(u.locked_until)) : null)),
            h("td", { class: "nowrap" }, timeEl(u.last_login_at)),
            h("td", { class: "num" }, fmtNum(u.run_count || 0)),
            h("td", { class: "num" }, u.failed_streak ? h("span", { class: "text-bad" }, fmtNum(u.failed_streak)) : "0"),
            h("td", null, acts));
        });
        const pending = users.filter((u) => u.status === "pending").length;
        replace(usersEl,
          pending ? h("div", { class: "banner banner-warn", style: { marginBottom: "12px" } }, `${plural(pending, "account")} waiting for approval.`) : null,
          h("div", { class: "table-wrap" }, h("table", { class: "data" },
            h("thead", null, h("tr", null, h("th", null, "User"), h("th", null, "Role"), h("th", null, "Status"), h("th", null, "Last sign-in"), h("th", { class: "num" }, "Runs"), h("th", { class: "num" }, "Failed attempts"), h("th", null, "Actions"))),
            h("tbody", null, rows))));
      } catch (e) {
        if (ctx.alive()) replace(usersEl, h("p", { class: "field-error" }, e.message));
      }
    }

    const KIND_BADGE = {
      login_ok: ["Sign-in", "badge-success"],
      login_fail: ["Failed sign-in", "badge-error"],
      login_blocked: ["Blocked attempt", "badge-error"],
      lockout: ["Account locked", "badge-error"],
      ip_block: ["IP blocked", "badge-error"],
      signup: ["Sign-up", "badge-beta"],
      logout: ["Sign-out", "badge-muted"],
    };

    async function loadEvents() {
      try {
        const data = await api("GET", "/api/admin/auth-events?limit=100");
        if (!ctx.alive()) return;
        const events = (data && data.events) || [];
        const blocked = ((data && data.blocked_ips) || []).filter((b) => !b.until || b.until > nowSec());
        replace(blockedEl, blocked.length ? h("div", { class: "banner banner-error", style: { marginBottom: "12px" } },
          h("div", null, h("strong", null, `${plural(blocked.length, "IP address", "IP addresses")} currently blocked: `),
            blocked.map((b, i) => h("span", null, i ? ", " : "", h("code", null, b.ip), b.until ? ` (until ${new Date(b.until * 1000).toLocaleTimeString()}) ` : " ",
              h("button", { type: "button", class: "btn btn-tertiary btn-sm", onclick: async () => {
                try {
                  await api("DELETE", `/api/admin/ip-blocks/${encodeURIComponent(b.ip)}`);
                  toast(`Unblocked ${b.ip}`, "success");
                  loadEvents();
                } catch (e) { toast(e.message || "Could not unblock", "error"); }
              } }, "Unblock"))))) : null);
        if (!events.length) { replace(eventsEl, emptyState("No sign-in activity", "Sign-ins, failures and lockouts will be listed here.")); return; }
        replace(eventsEl, h("div", { class: "table-wrap" }, h("table", { class: "data compact" },
          h("thead", null, h("tr", null, h("th", null, "Time"), h("th", null, "Event"), h("th", null, "IP"), h("th", null, "Username"), h("th", null, "Detail"))),
          h("tbody", null, events.map((ev) => {
            const kb = KIND_BADGE[ev.kind] || [ev.kind, "badge-muted"];
            return h("tr", null,
              h("td", { class: "nowrap" }, timeEl(ev.at)),
              h("td", null, badge(kb[0], kb[1] + " badge-sm")),
              h("td", null, h("code", null, ev.ip || "—")),
              h("td", null, ev.username || h("span", { class: "stone" }, "—")),
              h("td", { class: "small break" }, ev.detail || ""));
          })))));
      } catch (e) {
        if (ctx.alive()) replace(eventsEl, h("p", { class: "field-error" }, e.message));
      }
    }

    loadUsers();
    loadEvents();
  }

  // ════════════════════════════════════════════════════════════════════
  // 5f. View: Account
  // ════════════════════════════════════════════════════════════════════

  function viewAccount(root, ctx) {
    const profileEl = h("div");
    const render = (u) => {
      replace(profileEl, h("div", { class: "card" },
        h("div", { class: "row" }, h("span", { class: "avatar", style: { width: "48px", height: "48px", fontSize: "20px" } }, (u.username || "?").slice(0, 1)),
          h("div", null, h("div", { class: "card-title" }, u.username), h("div", { class: "row" },
            u.role === "admin" ? badge("Administrator", "badge-dark badge-sm") : badge("User", "badge-outline badge-sm"),
            u.status === "active" ? badge("Active", "badge-success badge-sm") : badge(u.status, "badge-warn badge-sm")))),
        h("dl", { class: "kv mt-md" },
          h("dt", null, "Member since"), h("dd", null, u.created_at ? absTime(u.created_at) : "—"),
          h("dt", null, "Last sign-in"), h("dd", null, u.last_login_at ? absTime(u.last_login_at) : "—"))));
    };
    render(S.user);
    api("GET", "/api/auth/me").then((me) => {
      if (!ctx.alive() || !me || !me.user) return;
      S.user = me.user;
      if (me.csrf) S.csrf = me.csrf;
      render(me.user);
    }).catch(() => { /* keep cached */ });

    const cur = h("input", { class: "input", type: "password", autocomplete: "current-password" });
    const nw = h("input", { class: "input", type: "password", autocomplete: "new-password", minlength: "10", maxlength: "256" });
    const nw2 = h("input", { class: "input", type: "password", autocomplete: "new-password" });
    const err = h("p", { class: "field-error hidden", role: "alert" });
    const btn = h("button", { type: "submit", class: "btn btn-primary" }, "Change password");
    const form = h("form", {
      class: "card stack", novalidate: true,
      onsubmit: async (e) => {
        e.preventDefault();
        err.classList.add("hidden");
        let msg = null;
        if (!cur.value) msg = "Enter your current password.";
        else if (nw.value.length < 10 || nw.value.length > 256) msg = "New password must be between 10 and 256 characters.";
        else if (nw.value !== nw2.value) msg = "New passwords do not match.";
        else if (nw.value === cur.value) msg = "The new password must differ from the current one.";
        if (msg) { err.textContent = msg; err.classList.remove("hidden"); return; }
        btn.disabled = true;
        try {
          await api("POST", "/api/auth/password", { current_password: cur.value, new_password: nw.value });
          form.reset();
          toast("Password changed. Other sessions were signed out.", "success");
        } catch (ex) {
          err.textContent = ex.message;
          err.classList.remove("hidden");
        } finally { btn.disabled = false; }
      },
    },
      h("h2", { class: "card-title" }, "Change password"),
      h("label", { class: "field" }, h("span", null, "Current password"), cur),
      h("label", { class: "field" }, h("span", null, "New password"), nw, h("small", { class: "field-hint" }, "At least 10 characters. Changing it signs out your other sessions.")),
      h("label", { class: "field" }, h("span", null, "Confirm new password"), nw2),
      err, h("div", null, btn));

    root.appendChild(h("div", { class: "container page", style: { maxWidth: "720px" } },
      h("div", { class: "page-head" }, h("div", null, h("h1", { class: "heading-lg" }, "Account"), h("p", { class: "muted" }, "Your profile and password."))),
      h("div", { class: "stack-lg" }, profileEl, form)));
  }

  // ════════════════════════════════════════════════════════════════════
  // Boot
  // ════════════════════════════════════════════════════════════════════

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
})();
