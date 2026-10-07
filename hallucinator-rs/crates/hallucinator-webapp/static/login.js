// hallucinator-webapp — sign-in page. Accounts are created by administrators
// (Admin page or `hallucinator-webapp create-user`); there is no self sign-up.
// Talks to /api/auth/{me,login} (see API.md). No inline handlers:
// everything is wired up here after DOMContentLoaded (script is `defer`).
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
    const res = await fetch(url, {
      method: "POST",
      credentials: "same-origin",
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
    } catch (_) {
      setError(err, "Network error — is the server running?");
    } finally {
      btn.textContent = "Sign in";
      if (!btn.dataset.locked) btn.disabled = false;
    }
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

    try {
      const res = await fetch("/api/auth/me", { credentials: "same-origin", headers: { Accept: "application/json" } });
      if (res.ok) {
        const me = await res.json();
        if (me && me.user) {
          location.replace("/");
          return;
        }
        if (me && me.bootstrap) showBootstrap();
      }
    } catch (_) {
      setNotice("Could not reach the server.", "error");
    }
    const params = new URLSearchParams(location.search);
    if (params.get("expired")) setNotice("Your session expired. Please sign in again.", "info");
    $("si-username").focus();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
