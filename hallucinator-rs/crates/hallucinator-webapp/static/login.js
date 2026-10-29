// hallucinator-webapp — sign-in page. Accounts are created by administrators
// (Admin page or `hallucinator-webapp create-user`); there is no self sign-up.
// Talks to /api/auth/{me,login} (see API.md) through HalluE2E (e2e.js): when
// the server requires end-to-end encryption, the key step comes first and
// every request goes sealed. No inline handlers: everything is wired up here
// after DOMContentLoaded (script is `defer`).
"use strict";

(function () {
  const $ = (id) => document.getElementById(id);
  const state = {
    lockTimer: null,
    lockUntil: 0,
  };

  // ── helpers ─────────────────────────────────────────────────────────
  function show(el, on) { el.classList.toggle("hidden", !on); }

  function setError(el, msg) {
    el.textContent = msg || "";
    show(el, !!msg);
  }

  function setNotice(msg, kind) {
    const el = $("notice");
    el.className = "banner banner-" + (kind || "info") + (msg ? "" : " hidden");
    el.textContent = msg || "";
  }

  async function postJSON(url, body) {
    const res = await HalluE2E.fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify(body),
    });
    let data = null;
    try { data = await res.json(); } catch (_) { data = null; }
    return { res, data };
  }

  function retryAfterOf(res, data) {
    if (data && Number.isFinite(data.retry_after)) return data.retry_after;
    const h = parseInt(res.headers.get("Retry-After") || "", 10);
    return Number.isFinite(h) ? h : 0;
  }

  function fmtCountdown(secs) {
    secs = Math.max(0, Math.ceil(secs));
    const h = Math.floor(secs / 3600);
    const m = Math.floor((secs % 3600) / 60);
    const s = secs % 60;
    const pad = (n) => String(n).padStart(2, "0");
    return h > 0 ? `${h}:${pad(m)}:${pad(s)}` : `${pad(m)}:${pad(s)}`;
  }

  // ── lockout banner with countdown ───────────────────────────────────
  function showLockout(message, retryAfter, buttons) {
    const box = $("lockout");
    clearInterval(state.lockTimer);
    box.textContent = "";
    const msg = document.createElement("span");
    msg.textContent = message || "Too many attempts. Please wait before trying again.";
    box.appendChild(msg);
    show(box, true);
    if (!retryAfter || retryAfter <= 0) return;

    state.lockUntil = Date.now() + retryAfter * 1000;
    const cd = document.createElement("span");
    cd.className = "countdown";
    cd.setAttribute("aria-live", "off");
    box.appendChild(cd);
    buttons = buttons || [$("si-submit")];
    buttons.forEach((b) => { b.disabled = true; b.dataset.locked = "1"; });

    const tick = () => {
      const left = (state.lockUntil - Date.now()) / 1000;
      if (left <= 0) {
        clearInterval(state.lockTimer);
        show(box, false);
        buttons.forEach((b) => { b.disabled = false; delete b.dataset.locked; });
        setNotice("You can try again now.", "info");
        return;
      }
      cd.textContent = fmtCountdown(left);
    };
    tick();
    state.lockTimer = setInterval(tick, 1000);
  }

  // ── sign in ─────────────────────────────────────────────────────────
  async function onSignin(e) {
    e.preventDefault();
    const err = $("si-error");
    setError(err, "");
    setNotice("");
    const username = $("si-username").value.trim();
    const password = $("si-password").value;
    if (!username || !password) {
      setError(err, "Enter your username and password.");
      return;
    }
    const btn = $("si-submit");
    btn.disabled = true;
    btn.textContent = "Signing in…";
    try {
      const { res, data } = await postJSON("/api/auth/login", { username, password });
      if (res.ok) {
        location.href = "/";
        return;
      }
      const msg = (data && data.error) || `Sign-in failed (HTTP ${res.status}).`;
      if (res.status === 429) {
        $("si-password").value = "";
        showLockout(msg, retryAfterOf(res, data), [$("si-submit")]);
      } else {
        setError(err, msg);
        if (res.status === 401) {
          $("si-password").value = "";
          $("si-password").focus();
        }
      }
    } catch (e) {
      if (e instanceof HalluE2E.E2EError) showKeyStep(e.message);
      else setError(err, "Network error — is the server running?");
    } finally {
      btn.textContent = "Sign in";
      if (!btn.dataset.locked) btn.disabled = false;
    }
  }

  // ── encryption key ──────────────────────────────────────────────────
  function showKeyStep(msg) {
    $("auth-heading").textContent = "Encryption key";
    document.title = "Encryption key · Hallucinator";
    show($("form-signin"), false);
    show($("form-key"), true);
    show($("key-plain-http"), HalluE2E.state.backend === "noble");
    setError($("key-error"), msg && msg !== HalluE2E.message("required") ? msg : "");
    $("key-value").focus();
  }

  function showSignin() {
    $("auth-heading").textContent = "Sign in";
    document.title = "Sign in · Hallucinator";
    show($("form-key"), false);
    show($("form-signin"), true);
    $("si-username").focus();
  }

  async function onKey(e) {
    e.preventDefault();
    const err = $("key-error");
    setError(err, "");
    const value = $("key-value").value;
    if (!value.trim()) {
      setError(err, "Enter the encryption key.");
      return;
    }
    const btn = $("key-submit");
    btn.disabled = true;
    try {
      await HalluE2E.enterKey(value);
      $("key-value").value = "";
      setNotice("Encryption key saved on this device.", "info");
      if (await signedIn()) return;
      showSignin();
    } catch (ex) {
      setError(err, ex.message || String(ex));
    } finally {
      btn.disabled = false;
    }
  }

  /** Go to the app when a session exists; show the bootstrap note when no account does. */
  async function signedIn() {
    const res = await HalluE2E.fetch("/api/auth/me", { headers: { Accept: "application/json" } });
    if (!res.ok) return false;
    const me = await res.json();
    if (me && me.user) {
      location.replace("/");
      return true;
    }
    if (me && me.bootstrap) showBootstrap();
    return false;
  }

  // No accounts exist yet: point at the shell command that creates the admin.
  function showBootstrap() {
    const el = $("notice");
    el.className = "banner banner-dark";
    el.textContent = "";
    const text = document.createElement("span");
    const cmd = document.createElement("code");
    cmd.textContent = "hallucinator-webapp create-user --username <name> --admin";
    text.append("No accounts exist yet. Create the administrator on the server, then sign in:", cmd);
    el.append(text);
  }

  // ── boot ────────────────────────────────────────────────────────────
  async function boot() {
    $("form-signin").addEventListener("submit", onSignin);
    $("form-key").addEventListener("submit", onKey);
    const params = new URLSearchParams(location.search);

    await HalluE2E.ready;
    // The app sends people here with ?e2e=<code> when an envelope failed.
    const code = params.get("e2e");
    if (HalluE2E.needsKey() || (code && HalluE2E.tunnel())) {
      showKeyStep(code ? HalluE2E.message(code) : "");
      return;
    }
    try {
      if (await signedIn()) return;
    } catch (e) {
      if (e instanceof HalluE2E.E2EError) {
        showKeyStep(e.message);
        return;
      }
      setNotice("Could not reach the server.", "error");
    }
    if (params.get("expired")) setNotice("Your session expired. Please sign in again.", "info");
    $("si-username").focus();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
