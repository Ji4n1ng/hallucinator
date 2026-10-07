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
./target/release/hallucinator-webapp            # http://127.0.0.1:5001
```

Open the page and **create the first account — it becomes the
administrator**. Later sign-ups wait for approval by default (`--signup`).

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
| `--signup open\|approval\|closed` | `approval` | who may create accounts |
| `--secure-cookies` | off | set when served over HTTPS |
| `--trust-proxy` | off | use `X-Forwarded-For` for rate limiting (only behind your own proxy) |
| `--cli-path` / `HALLUCINATOR_CLI` | auto | `hallucinator-cli` binary for DB jobs |
| `--max-concurrent-runs` | 2 | further submissions queue |
| `--max-upload-mb` | 200 | per submission |
| `--session-hours` | 168 | session lifetime |
| `--stale-after-days` | 30 | when a database is flagged stale |
| `--static-dir` | embedded | serve `static/` from disk (UI development) |

Account maintenance from the shell:

```bash
HALLUCINATOR_WEB_PASSWORD=… hallucinator-webapp create-user --username alice --admin
hallucinator-webapp reset-password --username alice   # also clears lockouts
```

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
- **Accounts** — sign-up/sign-in, admin approval, roles, password change.

## Security

- Argon2id password hashes; sessions are random 256-bit tokens stored only as
  SHA-256 hashes; `HttpOnly; SameSite=Lax` cookie (+ `Secure` with
  `--secure-cookies`); per-session CSRF token required on every state-changing
  API call; Origin check on sign-in/sign-up.
- **Brute-force protection**: 5 consecutive failures lock an account for 15
  minutes, doubling per repeated lockout up to 24 h (the password is not even
  verified while locked, so a locked account is no oracle); unknown usernames
  lock out identically so lockouts don't reveal which accounts exist; 20
  failures from one IP within 15 minutes block that IP for 30 minutes; at most
  5 sign-ups per IP per hour; generic error messages and equal-cost
  verification for unknown users. Admins see the sign-in audit log and can
  unlock accounts / unblock IPs.
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
  main.rs     flags, startup, create-user / reset-password
  api/        HTTP routes (contract: API.md) — auth, runs, dbs, admin
  auth.rs     hashing, sessions, CSRF, lockout policy
  store.rs    SQLite schema + queries (users, sessions, audit, history, jobs)
  runs.rs     check execution (ValidationPool, like the TUI backend) + SSE
  inputs.rs   upload pairing and the PDF+bib merge
  refdb.rs    offline DB discovery/loading/freshness, core Config builder
  jobs.rs     hallucinator-cli child processes for updates/imports
  export.rs   exports through hallucinator-reporting
  model.rs    serde mirror of ValidationResult, stats
static/       dependency-free UI (no build step), follows DESIGN.md
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
