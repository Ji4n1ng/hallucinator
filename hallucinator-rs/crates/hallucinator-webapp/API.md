# hallucinator-webapp HTTP API

Contract between the Rust server (`src/`) and the browser client (`static/`).
All JSON. Timestamps are **unix seconds** (integers). All `/api/*` routes
except the auth bootstrap ones require a session cookie.

## Conventions

- **Session**: `hallu_session` cookie (HttpOnly, SameSite=Lax). The client never
  reads it.
- **CSRF**: every non-GET request to `/api/*` must send header
  `X-CSRF-Token: <csrf>` where `<csrf>` comes from `GET /api/auth/me`.
  (`POST /api/auth/login` and `POST /api/auth/register` are exempt — no session
  exists yet; they are protected by an Origin check instead.)
- **Errors**: non-2xx responses carry `{"error": "<human readable message>"}`.
  `401` → not signed in (client redirects to `/login`), `403` → forbidden,
  `429` → rate limited / locked out (also sets `Retry-After` seconds header and
  includes `"retry_after": <secs>` in the JSON body).
- **SSE** endpoints use `text/event-stream`; each message has an `event:` name
  and a JSON `data:` payload.

## Pages (HTML)

| Path | Description |
|---|---|
| `GET /login` | Sign-in / create-account page (`static/login.html`). |
| `GET /` | App shell (`static/index.html`); redirects to `/login` without a session. |
| `GET /static/<file>` | Static assets (`app.css`, `app.js`, `login.js`, `logo.svg`). |

The app shell is a hash-routed SPA:
`#/` new check · `#/runs/<id>` run view · `#/history` · `#/databases` ·
`#/admin` (admins) · `#/account`.

## Auth

### `GET /api/auth/me`  (no session required)
```json
{
  "user": User | null,
  "csrf": "string | null",
  "signup_mode": "open" | "approval" | "closed",
  "bootstrap": true        // no users exist yet: first account becomes admin
}
```
`User = {"id":1,"username":"alice","role":"admin"|"user","status":"active"|"pending"|"disabled","created_at":0,"last_login_at":0|null}`

### `POST /api/auth/register`  `{"username","password"}`
- username: `^[A-Za-z0-9_.-]{3,32}$`; password: 10–256 chars.
- `201 {"user": User, "message": "..."}`. When `user.status == "pending"`
  the account waits for admin approval and **no session is created**;
  otherwise the response also sets the session cookie (auto sign-in).
- `409` username taken, `403` sign-up closed, `429` too many sign-ups from this IP.

### `POST /api/auth/login`  `{"username","password"}`
- `200 {"user": User}` + session cookie.
- `401 {"error":"Invalid username or password."}` (generic, never reveals which).
- `403` account pending approval / disabled (only after a correct password).
- `429 {"error":"Too many failed sign-in attempts. Try again in 15 minutes.","retry_after":900}`
  — per-account lockout (5 failures / 15 min, doubling on repeat lockouts, max 24 h)
  or per-IP block (20 failures / 15 min → 30 min block).

### `POST /api/auth/logout` → `204`
### `POST /api/auth/password` `{"current_password","new_password"}` → `204` (other sessions revoked)
A wrong current password is `400` (never `401`, which the client treats as an expired session).

## Configuration

### `GET /api/options`
Defaults and choices for the new-check form.
```json
{
  "databases": [ {"name":"CrossRef","enabled_by_default":true,"offline":false,"available":true,"note":""} , ...],
  "defaults": {"disabled_dbs":["Open Library"],"url_match":false,"searxng":false,"check_openalex_authors":false,"num_workers":4},
  "searxng_configured": false,
  "max_upload_mb": 200,
  "accepted": [".pdf",".bib",".bbl",".xml",".zip",".tar.gz",".tgz"]
}
```

## Runs (a "run" = one submission of one or more papers)

### `POST /api/runs`  (multipart/form-data)
Fields:
- `files` — one or more files (repeat the field). `.pdf`, `.bib`, `.bbl`,
  `.xml` (GROBID TEI), `.zip`, `.tar.gz`/`.tgz` (expanded server-side).
- `options` — JSON string:
  ```json
  {
    "title": "optional run title",
    "disabled_dbs": ["Open Library"],
    "url_match": false,
    "searxng": false,
    "check_openalex_authors": false,
    "bib_mode": "merge" | "separate"
  }
  ```
  **Pairing**: a `.bib`/`.bbl` whose file stem equals a PDF's stem — or, when
  the upload has exactly one PDF and one `.bib`/`.bbl`, that pair — is attached
  to the PDF as its *companion*. With `bib_mode:"merge"` (default) the PDF
  decides **which** references are cited and the companion supplies clean
  structured fields (title, authors, DOI, arXiv id, URLs) for every reference it
  matches; unmatched PDF references keep the PDF parse. With `"separate"` every
  file is checked on its own. Unpaired `.bib`/`.bbl`/`.xml` files are always
  checked on their own (all entries).
- `201 {"run_id":"9f2c..."}`. Then open `#/runs/<id>`.

### `GET /api/runs?q=&status=&limit=50&offset=0&all=0`
History list (own runs; admins may pass `all=1` for everyone's).
```json
{ "total": 12, "runs": [ RunSummary, ... ] }
```
`RunSummary`:
```json
{
  "id":"9f2c...", "title":"paper.pdf", "status":"queued|running|done|cancelled|failed|interrupted",
  "username":"alice", "created_at":0, "started_at":0|null, "finished_at":0|null,
  "paper_count":1, "error":null,
  "stats": Stats
}
```
`Stats` (all integers; computed over every paper of the run, or one paper):
```json
{"total":0,"checked":0,"pending":0,"verified":0,"not_found":0,"mismatch":0,
 "author_mismatch":0,"doi_mismatch":0,"arxiv_mismatch":0,"retracted":0,
 "skipped":0,"inconclusive":0,"marked_safe":0,"problems":0}
```
`problems` = not_found + mismatch + retracted − (those marked safe). `marked_safe`
counts refs with `fp_reason` set. `checked` = refs with a result; `pending` =
checkable refs without a result yet.

### `GET /api/runs/:id`  → `RunDetail`
```json
{
  "run": RunSummary & {"options": {...the options JSON...}},
  "papers": [ Paper, ... ]
}
```
`Paper`:
```json
{
  "idx":0, "filename":"paper.pdf",
  "input_kind":"pdf|bib|bbl|xml|pdf+bib|pdf+bbl",
  "companion_filename":"paper.bib"|null,
  "status":"queued|extracting|checking|done|failed|cancelled",
  "error":null, "verdict":"safe"|"questionable"|null,
  "stats": Stats,
  "skip_stats": {"url_only":0,"short_title":0,"no_title":0,"no_authors":0,"total_raw":0} | null,
  "merge": {"companion":"paper.bib","companion_entries":120,"pdf_refs":48,"matched":45,"pdf_only":3,"fallback":null|"pdf_failed"} | null,
  "refs": [ Ref, ... ]
}
```
`Ref`:
```json
{
  "idx":0, "original_number":1,
  "title":"..."|null, "raw_citation":"...", "authors":["..."],
  "doi":null, "arxiv_id":null, "urls":[], "skip_reason":null|"url_only"|"short_title"|"no_title",
  "origin":"pdf"|"bib"|"bbl"|"xml",
  "phase":"skipped|pending|checking|retrying|done",
  "verdict":"verified|not_found|mismatch|inconclusive|skipped"|null,
  "retracted":false,
  "fp_reason":null|"broken_parse"|"exists_elsewhere"|"all_timed_out"|"known_good"|"non_academic",
  "live_dbs":[{"db":"CrossRef","status":"match|no_match|author_mismatch|timeout|rate_limited|error|skipped","elapsed_ms":120}],
  "result": Result | null
}
```
`Result` (lossless mirror of `hallucinator_core::ValidationResult`):
```json
{
  "title":"...", "raw_citation":"...", "ref_authors":["..."],
  "status":"verified|not_found|mismatch", "mismatch":["author","doi","arxiv_id"],
  "source":"DBLP"|null, "found_authors":["..."], "paper_url":"https://..."|null,
  "failed_dbs":["Semantic Scholar"],
  "db_results":[{"db":"DBLP","status":"match","elapsed_ms":12,"found_authors":[],"paper_url":null,"error":null}],
  "doi_info":{"doi":"10...","valid":true,"title":"..."}|null,
  "arxiv_info":{"arxiv_id":"2401.00001","valid":true,"title":"..."}|null,
  "retraction_info":{"is_retracted":true,"retraction_doi":"...","retraction_source":"..."}|null,
  "url_check_skipped":false
}
```
FP reason labels (for UI): broken_parse "Broken citation parse", exists_elsewhere
"Found on Google Scholar / other source", all_timed_out "All databases timed out",
known_good "User verified as real", non_academic "Non-academic source (RFC, legal, news, etc.)".

### `GET /api/runs/:id/events`  (SSE)
First message is always `snapshot` (a full `RunDetail`). Then incremental:

| event | data |
|---|---|
| `snapshot` | `RunDetail` |
| `run` | `{"status":"running","started_at":0,"finished_at":null,"error":null}` |
| `paper` | `{"paper_idx":0,"status":"checking","error":null,"stats":Stats,"verdict":null,"merge":{...}|null,"skip_stats":{...}|null,"input_kind":"pdf+bib"}` |
| `refs` | `{"paper_idx":0,"refs":[Ref,...]}` — full ref list, sent once extraction finishes |
| `ref` | `{"paper_idx":0,"ref":Ref,"stats":Stats}` — one ref changed (phase/result/fp) |
| `db` | `{"paper_idx":0,"ref_idx":3,"db":"CrossRef","status":"no_match","elapsed_ms":340}` |
| `notice` | `{"level":"info|warn|error","message":"..."}` |
| `end` | `{}` — run finished and nothing else will be sent; client may close |

### `POST /api/runs/:id/cancel` → `204`
### `DELETE /api/runs/:id` → `204` (cancels first if running)
### `POST /api/runs/:id/papers/:pidx/retry`  `{"scope":"failed"|"not_found"|"problems"|"ref","ref_idx":3}`
Re-checks refs (`failed`: refs whose result has failed DBs — only those DBs are
re-queried; `not_found`/`problems`: full re-check; `ref`: the single ref). `202 {"queued": N}`.
Progress arrives on the run's SSE stream (reconnect if it had ended).
### `PUT /api/runs/:id/papers/:pidx/refs/:ridx/fp`  `{"reason": "known_good" | null}` → `200 {"ref":Ref,"stats":Stats}`
### `PUT /api/runs/:id/papers/:pidx/verdict` `{"verdict":"safe"|"questionable"|null}` → `204`
### `GET /api/runs/:id/export?format=json|csv|markdown|text|html&paper=<idx>&problematic=0|1`
File download (uses upstream `hallucinator-reporting`; JSON output is loadable by
`hallucinator-tui --load`). Omit `paper` to export every paper of the run.

## Reference databases

### `GET /api/databases`
```json
{
  "cli_available": true, "cli_path": "/.../hallucinator-cli", "cli_version":"0.2.4",
  "config_path": "/home/u/.config/hallucinator/config.toml" | null,
  "databases": [ DbStatus, ... ],
  "cache": {"path":"...","exists":true,"size_bytes":0,"entries":null},
  "venues": [ {"key":"usenix","subcommand":"import-usenix","about":"Import a USENIX ...","input":"url"|"pdf"} ],
  "marked_safe_count": 7
}
```
`DbStatus`:
```json
{
  "key":"dblp|acl|arxiv|iacr|openalex|corpus", "label":"DBLP",
  "description":"Computer science bibliography (offline SQLite + FTS5)",
  "path":"/home/u/.local/share/hallucinator/dblp.db",
  "path_source":"env|config|auto|default",
  "exists":true, "size_bytes":2790932480, "modified_at":0,
  "loaded":true, "load_error":null,
  "build_date":"2026-08-17T18:55:00Z"|null, "age_days":50|null, "stale":true,
  "records":[{"label":"publications","count":7000000}],
  "update": {"supported":true,"action":"update"|"import","notes":"~4.6 GB download ...",
             "params":[{"name":"from_file","label":"Use local dblp.xml.gz","kind":"path","required":false}]},
             // param kinds: path | text | number | date | bool
  "active_job": Job | null,
  "last_job": Job | null
}
```
Local corpus extra: `"sources":[{"source":"usenix2026","count":420}]`.

**Non-admins never see server paths.** For them `cli_path`, `config_path` and
`cache.path` are `null`; `DbStatus` has no `path`/`path_source`; `load_error`
is a generic message; and `Job.argv` is omitted (here and in `GET /api/jobs`).

### `POST /api/databases/:key/update`  (admin) `{"params": {"from_file": "/path"}}` → `202 {"job": Job}`
### `POST /api/databases/corpus/import`  (admin) `{"venue":"usenix","source_tag":"usenix2026","url":"https://..."}` or `{"venue":"chi","source_tag":"chi2026","pdf_path":"/srv/chi.pdf"}` → `202 {"job": Job}`
### `POST /api/databases/corpus/import-marked-safe` (admin) → `202 {"job": Job}`
Imports every reference marked safe in the run history into the local corpus.
### `POST /api/databases/cache/clear` (admin) `{"not_found_only": true}` → `200 {"removed": N|null}`

### Jobs
`Job = {"id":"..","db_key":"dblp","action":"update|import","label":"Update DBLP","argv":["update-dblp","/path"],"status":"running|succeeded|failed|cancelled|interrupted","created_at":0,"finished_at":null,"exit_code":null,"username":"alice"}`

- `GET /api/jobs?limit=20` → `{"jobs":[Job]}`
- `GET /api/jobs/:id` (admin — logs print server paths) → `{"job":Job,"log":"full text"}`
- `GET /api/jobs/:id/events` (admin, SSE): `snapshot` `{"job":Job,"log":"..."}`, then `line` `{"line":"..."}`, `status` `{"job":Job}`, `end` `{}`
- `POST /api/jobs/:id/cancel` (admin) → `204`

## Admin

- `GET /api/admin/users` → `{"users":[User & {"locked_until":0|null,"failed_streak":0,"run_count":3}]}`
- `PATCH /api/admin/users/:id` `{"status":"active|disabled","role":"admin|user","unlock":true}` (any subset) → `{"user":User}`
- `POST /api/admin/users` `{"username","password","role"}` → `201 {"user":User}`
- `DELETE /api/admin/users/:id` → `204` (cannot delete yourself)
- `DELETE /api/admin/ip-blocks/:ip` → `204` (lift an IP block early)
- `GET /api/admin/auth-events?limit=100` → `{"events":[{"id":1,"at":0,"ip":"1.2.3.4","username":"bob","kind":"login_ok|login_fail|login_blocked|lockout|signup|logout|ip_block","detail":null}],"blocked_ips":[{"ip":"1.2.3.4","until":0}]}`
