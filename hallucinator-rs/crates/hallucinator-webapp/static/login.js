// hallucinator-webapp — sign-in / create-account page.
// Talks to /api/auth/{me,login,register} (see API.md). No inline handlers:
// everything is wired up here after DOMContentLoaded (script is `defer`).
"use strict";

(function () {
  const $ = (id) => document.getElementById(id);
  const USERNAME_RE = /^[A-Za-z0-9_.-]{3,32}$/;

  const state = {
    signupMode: "closed",
    bootstrap: false,
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
    buttons = buttons || [$("si-submit"), $("su-submit")];
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

  // ── tabs ────────────────────────────────────────────────────────────
  function selectTab(which) {
    const signin = which === "signin";
    $("tab-signin").setAttribute("aria-selected", String(signin));
    $("tab-signup").setAttribute("aria-selected", String(!signin));
    show($("form-signin"), signin);
    show($("form-signup"), !signin);
    setError($("si-error"), "");
    setError($("su-error"), "");
    const first = signin ? $("si-username") : $("su-username");
    first.focus();
  }

  function setupTabs() {
    const canSignup = state.bootstrap || state.signupMode !== "closed";
    show($("tab-signup"), canSignup);
    const note = $("su-note");
    if (state.bootstrap) {
      note.textContent = "No accounts exist yet. The first account you create becomes the administrator.";
      note.className = "banner banner-dark";
    } else if (state.signupMode === "approval") {
      note.textContent = "New accounts must be approved by an administrator before you can sign in.";
      note.className = "banner banner-info";
    } else {
      note.className = "banner hidden";
    }
    $("tab-signin").addEventListener("click", () => selectTab("signin"));
    $("tab-signup").addEventListener("click", () => selectTab("signup"));
    // Arrow-key navigation between tabs (WAI-ARIA tabs pattern)
    const tabs = [$("tab-signin"), $("tab-signup")];
    tabs.forEach((t, i) => t.addEventListener("keydown", (e) => {
      if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
      const visible = tabs.filter((x) => !x.classList.contains("hidden"));
      if (visible.length < 2) return;
      const next = visible[(visible.indexOf(t) + 1) % visible.length];
      next.click();
      next.focus();
      e.preventDefault();
    }));
    if (state.bootstrap) selectTab("signup");
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

  // ── sign up ─────────────────────────────────────────────────────────
  function pwStrength(pw) {
    let score = 0;
    if (pw.length >= 10) score++;
    if (pw.length >= 14) score++;
    if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++;
    if (/\d/.test(pw)) score++;
    if (/[^A-Za-z0-9]/.test(pw)) score++;
    return Math.min(score, 4);
  }

  function updateMeter() {
    const pw = $("su-password").value;
    const s = pw ? pwStrength(pw) : 0;
    const colors = ["#d45656", "#d45656", "#a15c00", "#1ba673", "#1ba673"];
    const bar = $("su-meter");
    bar.style.width = (pw ? (s + 1) * 20 : 0) + "%";
    bar.style.background = colors[s];
  }

  async function onSignup(e) {
    e.preventDefault();
    const err = $("su-error");
    setError(err, "");
    setNotice("");
    const username = $("su-username").value.trim();
    const password = $("su-password").value;
    const password2 = $("su-password2").value;
    $("su-username").classList.remove("invalid");
    $("su-password").classList.remove("invalid");
    $("su-password2").classList.remove("invalid");

    if (!USERNAME_RE.test(username)) {
      $("su-username").classList.add("invalid");
      setError(err, "Username must be 3–32 characters: letters, digits, _ . -");
      return;
    }
    if (password.length < 10 || password.length > 256) {
      $("su-password").classList.add("invalid");
      setError(err, "Password must be between 10 and 256 characters.");
      return;
    }
    if (password !== password2) {
      $("su-password2").classList.add("invalid");
      setError(err, "Passwords do not match.");
      return;
    }

    const btn = $("su-submit");
    btn.disabled = true;
    btn.textContent = "Creating account…";
    try {
      const { res, data } = await postJSON("/api/auth/register", { username, password });
      if (res.ok) {
        const user = data && data.user;
        if (user && user.status === "pending") {
          $("form-signup").reset();
          updateMeter();
          selectTab("signin");
          $("si-username").value = username;
          setNotice((data && data.message) ||
            "Account created. An administrator must approve it before you can sign in.", "success");
          return;
        }
        location.href = "/";
        return;
      }
      const msg = (data && data.error) || `Could not create account (HTTP ${res.status}).`;
      if (res.status === 429) {
        showLockout(msg, retryAfterOf(res, data), [$("su-submit")]);
      } else {
        if (res.status === 409) $("su-username").classList.add("invalid");
        setError(err, msg);
      }
    } catch (_) {
      setError(err, "Network error — is the server running?");
    } finally {
      btn.textContent = "Create account";
      if (!btn.dataset.locked) btn.disabled = false;
    }
  }

  // ── boot ────────────────────────────────────────────────────────────
  async function boot() {
    $("form-signin").addEventListener("submit", onSignin);
    $("form-signup").addEventListener("submit", onSignup);
    $("su-password").addEventListener("input", updateMeter);

    try {
      const res = await fetch("/api/auth/me", { credentials: "same-origin", headers: { Accept: "application/json" } });
      if (res.ok) {
        const me = await res.json();
        if (me && me.user) {
          location.replace("/");
          return;
        }
        state.signupMode = (me && me.signup_mode) || "closed";
        state.bootstrap = !!(me && me.bootstrap);
      }
    } catch (_) {
      setNotice("Could not reach the server.", "error");
    }
    setupTabs();
    const params = new URLSearchParams(location.search);
    if (params.get("expired")) setNotice("Your session expired. Please sign in again.", "info");
    if (!state.bootstrap) $("si-username").focus();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
