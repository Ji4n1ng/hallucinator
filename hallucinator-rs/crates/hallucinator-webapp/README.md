# hallucinator-webapp

A multi-user web interface for the hallucinated reference detector — the
TUI's workflow in a browser, plus accounts, a persistent check history,
`.bib` support and a page to keep the offline reference databases fresh.

> **Fork-only crate.** It lives in its own Cargo workspace and depends on the
> upstream crates by path, so merging upstream never conflicts with it. See
> [Keeping up with upstream](#keeping-up-with-upstream).

## Quick start

```bash
# 1. The upstream CLI (used for database updates/imports)
cd hallucinator-rs
cargo build --release -p hallucinator-cli

# 2. The web app
cd crates/hallucinator-webapp
cargo build --release
HALLUCINATOR_WEB_PASSWORD=… ./target/release/hallucinator-webapp create-user --username alice --admin
./target/release/hallucinator-webapp            # http://127.0.0.1:5001
```

There is no self sign-up: **create the first administrator from the shell**
(above), then add further accounts on the Admin page.

The app reads the same configuration as the CLI/TUI
(`~/.config/hallucinator/config.toml`, overlaid by `./.hallucinator.toml`):
API keys, offline database paths, disabled databases, timeouts. Offline
databases not named in the config are auto-detected in
`~/.local/share/hallucinator/` exactly like the TUI does.

### Options

| Flag / env | Default | |
|---|---|---|
| `--bind` / `HALLUCINATOR_WEB_BIND` | `127.0.0.1:5001` | listen address |
| `--data-dir` / `HALLUCINATOR_WEB_DATA` | `~/.local/share/hallucinator/webapp` | accounts, history (`webapp.db`), query cache |
| `--config` | auto | hallucinator `config.toml` |
| `--secure-cookies` | off | set when served over HTTPS |
| `--trust-proxy` | off | use `X-Forwarded-For` for rate limiting (only behind your own proxy) |
| `--cli-path` / `HALLUCINATOR_CLI` | auto | `hallucinator-cli` binary for DB jobs |
| `--max-concurrent-runs` | 2 | further submissions queue |
| `--max-upload-mb` | 200 | per submission |
| `--session-hours` | 168 | session lifetime |
| `--stale-after-days` | 30 | when a database is flagged stale |
| `--static-dir` | embedded | serve `static/` from disk (UI development) |
| `--e2e-key-file` / `HALLUCINATOR_E2E_KEY_FILE` | off | end-to-end encryption key (`cek1_…`, mode 600); when set, every API call and page request that holds data must come through the tunnel |
| `--e2e-key-previous-file` / `HALLUCINATOR_E2E_KEY_PREVIOUS_FILE` | off | the previous key during a rotation |

Account maintenance from the shell:

```bash
HALLUCINATOR_WEB_PASSWORD=… hallucinator-webapp create-user --username alice --admin
hallucinator-webapp reset-password --username alice   # also clears lockouts
hallucinator-webapp create-token --username alice --name "laptop"   # prints an API token (people's accounts)
```

Agent accounts (one per Catelier agent, kind `agent`, role `user`, no
password, never an admin) and their tokens. A token goes only to standard
output, which must be a pipe, so it is never shown:

```bash
hallucinator-webapp agent add Frieren Fern …      # create agent accounts
hallucinator-webapp agent list                    # accounts and token prefixes
hallucinator-webapp agent issue Frieren | catelier-admin tool token hallucinator Frieren
hallucinator-webapp agent rotate Frieren | catelier-admin tool token hallucinator Frieren
hallucinator-webapp agent revoke Frieren          # works at once, no restart
```

### End-to-end encryption

Catelier's E2E protocol v1 (`src/e2e.rs`, `static/e2e.js`; the agent tool
standard). HTTPS does not replace it: Cloudflare and other proxies end TLS
and can read the traffic.

```bash
hallucinator-webapp e2e-key new ~/.config/hallucinator/e2e.key   # mode 600; prints only the key id
# in the unit: Environment=HALLUCINATOR_E2E_KEY_FILE=%h/.config/hallucinator/e2e.key
deploy/install-user-service.sh 0.0.0.0:8301 ~/.config/hallucinator/e2e.key
```

With a key, plain API calls get `400 {"e2e":"required"}`; `GET /api/health`
lists the key ids. Browsers show a key screen first (type the `cek1_…` key
once per device); then every request goes sealed and live progress comes
by polling. On plain http (a LAN address) the browser has no WebCrypto, so
the vendored `static/noble.js` does the AES-GCM, and the key is kept where
scripts on the page can read it. Agents call through `taskctl tool
hallucinator …`. To rotate: make a new key, move the old file to
`--e2e-key-previous-file`, restart, update clients, then drop the old one.

### Running in the background

`deploy/install-user-service.sh` installs a systemd **user** service (no
root). The service restarts after a crash, starts at boot and keeps running
after you log out:

```bash
cargo build --release
deploy/install-user-service.sh 0.0.0.0:8301      # bind address; default 127.0.0.1:5001

systemctl --user status hallucinator-webapp
journalctl --user -u hallucinator-webapp -f      # logs
systemctl --user restart hallucinator-webapp     # after rebuilding
```

To change the address, run the script again. Other flags can be set through
their env vars in `~/.config/systemd/user/hallucinator-webapp.service`.
Edit them there, then run `systemctl --user daemon-reload`. If `systemctl
--user` reports `Failed to connect to bus` from a tmux or SSH shell, first
run `export XDG_RUNTIME_DIR=/run/user/$(id -u)`.

For anything beyond localhost put it behind a TLS reverse proxy and run with
`--secure-cookies --trust-proxy`. Disable proxy buffering for
`/api/*/events` (the app sends `X-Accel-Buffering: no` for nginx).

## Features

- **Checks** — upload PDFs, `.bib`, `.bbl`, GROBID `.xml`, `.zip`/`.tar.gz`
  archives. Progress streams live per reference and per database; results
  match `hallucinator-cli check` (same engine, same `ValidationPool`).
- **PDF + .bib** — a `.bib`/`.bbl` with the same file stem as a PDF (or the
  only pair in an upload) is merged with it: the PDF decides *which*
  references are cited, the `.bib` supplies clean titles, authors, DOIs, arXiv
  ids and URLs for every reference it matches (fuzzy title match, including
  inside the raw PDF citation when PDF title extraction failed). Unmatched PDF
  references keep the PDF parse; uncited `.bib` entries are not checked. A
  `.bib` uploaded alone is checked entry by entry.
- **Review** — filter/search references, mark false positives with the TUI's
  reasons, set a paper verdict, re-check failed databases / not-found /
  problematic / single references, export JSON (loadable by
  `hallucinator-tui --load`), CSV, Markdown, text or HTML via upstream
  `hallucinator-reporting`.
- **History** — every run, paper, reference and result is stored in SQLite as
  it arrives; runs survive restarts (interrupted runs are marked as such).
  Users see their own runs; admins can see everyone's.
- **Databases** — path, size, build date/age, record counts and load status
  of DBLP, ACL, arXiv, IACR ePrint, OpenAlex and the local corpus; admins can
  run updates and local-corpus imports (venue program pages, or every
  reference marked safe in the history) with a live log, and clear the query
  cache. Databases are reloaded automatically when a job finishes.
- **Accounts** — created by administrators only (Admin page or
  `create-user`); roles, disabling, password change.
- **API for scripts and agents** — personal API tokens (Account page or
  `create-token`) sent as `Authorization: Bearer`; long-polling
  (`?wait=<secs>`) and a compact per-reference report
  (`GET /api/runs/:id/report`). The server documents itself at
  `GET /api/docs` (also `/llms.txt`; source [API-GUIDE.md](API-GUIDE.md)) and
  `GET /api/docs/reference` ([API.md](API.md)).

## Security

- Argon2id password hashes; sessions and API tokens are random 256-bit
  tokens stored only as SHA-256 hashes; `HttpOnly; SameSite=Lax` cookie (+ `Secure` with
  `--secure-cookies`); per-session CSRF token required on every state-changing
  API call; Origin check on sign-in.
- **Brute-force protection**: 5 consecutive failures lock an account for 15
  minutes, doubling per repeated lockout up to 24 h (the password is not even
  verified while locked, so a locked account is no oracle); unknown usernames
  lock out identically so lockouts don't reveal which accounts exist; 20
  failures from one IP within 15 minutes block that IP for 30 minutes;
  generic error messages and equal-cost
  verification for unknown users. Admins see the sign-in audit log and can
  unlock accounts / unblock IPs.
- API tokens act with their owner's permissions and skip CSRF (browsers
  never attach `Authorization` on their own). A wrong token is a 401 with no
  cookie fallback. Tokens cannot sign out, change the password or manage
  tokens, so a leaked one cannot mint more; disabling the account stops its
  tokens. Agents use agent accounts (never admins).
- End-to-end encryption (optional, see above): sealed envelopes with replay
  and clock checks; an address whose envelopes fail to decrypt 10 times in
  10 minutes is refused for 15 minutes; a session cookie sent plain ends
  its session.
- Audit log of every agent call and every change (Admin page,
  `GET /api/admin/audit`), kept 90 days; no query strings or bodies.
- Strict CSP (no inline script), `nosniff`, `frame-ancestors 'none'`; the UI
  never inserts server data as HTML; exports are served as sandboxed
  attachments; uploads are validated, kept in a temp dir only while being
  extracted, and never stored.
- DB jobs run `hallucinator-cli` with an argv built from validated input
  (whitelisted venues, tag/URL/path checks); admin only.
- Server filesystem paths (databases, config, cache, CLI), job command lines
  and job logs are shown to admins only; other users see each database's
  status, dates and record counts.

## Architecture

```
src/
  main.rs     flags, startup, create-user / reset-password / create-token
  api/        HTTP routes (contract: API.md) — auth, tokens, runs, dbs, admin, docs
  auth.rs     hashing, sessions, API tokens, CSRF, lockout policy
  store.rs    SQLite schema + queries (users, sessions, audit, history, jobs)
  runs.rs     check execution (ValidationPool, like the TUI backend) + SSE
  inputs.rs   upload pairing and the PDF+bib merge
  refdb.rs    offline DB discovery/loading/freshness, core Config builder
  jobs.rs     hallucinator-cli child processes for updates/imports
  export.rs   exports through hallucinator-reporting
  model.rs    serde mirror of ValidationResult, stats
static/       dependency-free UI (no build step), follows DESIGN.md
API-GUIDE.md  agent/script guide, served at /api/docs
deploy/       systemd user-service installer
```

## Keeping up with upstream

The fork touches upstream code in exactly one place:
`crates/hallucinator-bbl` now fills `Reference::urls` for `.bib` entries
(`url`, `\url{}` in `howpublished`/`note`) and `.bbl` entries — previously
always empty, so web citations from bibliographies could never use the URL
fallback. It is a small, self-contained change worth sending upstream.

Everything else is additive: this crate (own `[workspace]` and
`Cargo.lock`), and nothing in upstream's `Cargo.toml`/`Cargo.lock`.

```bash
git fetch upstream && git merge upstream/main
cd hallucinator-rs && cargo build --release -p hallucinator-cli
cd crates/hallucinator-webapp && cargo test && cargo build --release
```

Things to re-check when upstream changes them:

| Upstream change | Where this crate depends on it |
|---|---|
| New/renamed database backend | `BACKENDS` in `src/api/runs.rs` (mirrors the TUI list; upstream keeps the real one `pub(crate)`) |
| New offline database type | `SPECS` / `Pools` in `src/refdb.rs` |
| `hallucinator_core::Config` fields | `RefDbRegistry::build_config` (compile error if missing) |
| `ValidationResult` fields | `model.rs` mirror (compile error if missing) |
| New `import-<venue>` CLI subcommand | nothing — discovered from `hallucinator-cli --help` at startup |
| `update-*` CLI flags | `api/dbs.rs::update` |
