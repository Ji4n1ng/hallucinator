# Hallucinator agent guide

## Quick start

Hallucinator checks every reference of an academic paper against CrossRef,
arXiv, DBLP, Semantic Scholar, OpenAlex, PubMed, ACL Anthology and offline
indexes. It flags references that no database has (possible fabrications),
whose authors, DOI or arXiv id do not match, or that were retracted.

Call it with `taskctl tool hallucinator METHOD PATH [--json '{…}']`. Each call
goes sealed through the end-to-end tunnel and carries your agent token, so you
never handle a URL, key or token. Read one part of this guide with
`taskctl tool hallucinator guide --section <slug>`: `check-access`,
`check-a-paper`, `read-the-report`, `follow-ups`, `limits-and-rules`, or a
reference part (`reference-service`, `reference-runs`, …).

## Check access

```bash
taskctl tool hallucinator whoami        # = GET /api/agent/whoami
# {"name":"Frieren","kind":"agent","role":"user"}
```

`401` means your token is missing, revoked or expired. Tell a person. Do not
make a token yourself.

## Check a paper

1. Submit the files as JSON. Give each file as `text` (`.bib`, `.bbl`,
   `.xml`) or `base64` (`.pdf`, `.zip`, `.tar.gz`). Write the body to a file
   and send it with `--data-file` (a `.json` file goes as JSON):

   ```bash
   python3 - > run.json <<'EOF'
   import base64, json
   pdf = base64.b64encode(open("paper.pdf", "rb").read()).decode()
   print(json.dumps({"files": [{"name": "paper.pdf", "base64": pdf},
                               {"name": "paper.bib", "text": open("paper.bib").read()}],
                     "options": {"title": "paper v3"}}))
   EOF
   taskctl tool hallucinator POST /api/runs --data-file run.json
   # {"run_id":"9f2c…","links":{"report":"/api/runs/9f2c…/report",…}}
   ```

   For references you only have as text, write them as BibTeX first (one
   `.bib` file is enough). For the user's own paper, send the PDF with its
   `.bib` of the same file stem: the PDF decides which references are cited
   and the `.bib` gives clean fields.

2. Wait for the compact report. `wait` blocks up to that many seconds until
   the run is done. Keep it under `taskctl tool`'s read timeout (120 s;
   raise it with `--timeout`):

   ```bash
   taskctl tool hallucinator GET '/api/runs/9f2c…/report?wait=100'
   ```

   If `run.done` is `false`, call it again. Most references take seconds.
   References that are not found can keep a run open for several minutes
   while rate-limited databases back off (a 50-reference paper: under a
   minute to about 7 minutes).

## Read the report

```json
{"run": {"id": "9f2c…", "status": "done", "done": true, "needs_attention": 2,
         "summary": "Run done: 48 references, 45 verified, 1 not found, …",
         "web_path": "/#/runs/9f2c…"},
 "papers": [{"idx": 0, "filename": "refs.bib", "refs": [
   {"idx": 17, "number": 18, "verdict": "not_found", "needs_attention": true,
    "reason": "Not found in any database: possibly fabricated, or …",
    "title": "…", "authors": ["…"], "raw_citation": "[18] …"}]}]}
```

`papers[].refs` lists only the references that need attention (`?refs=all`
lists all, `?refs=none` none). `idx` is what the URLs use; `number` is the
number in the paper.

| `verdict` | Meaning | What to do |
|---|---|---|
| `verified` | Found, authors match | nothing |
| `not_found` | No database has it | Strongest fabrication signal, but also books, theses, standards and very new work. Search the web before you call it fake. |
| `mismatch` | Title found; authors, DOI or arXiv id differ | Compare `found_authors` and `paper_url` with the citation. |
| `inconclusive` | Not found while some databases failed (`failed_dbs`) | Retry (below), then judge. |
| `skipped` | Not checked (no title, short title, URL only, web page) | Read `reason`; check by hand if it matters. |
| `pending` | Not checked yet | Wait. |

`retracted: true` can come with any verdict. Report problems as "could not
be verified", with the reason, and let a person decide. Never call a paper
fabricated on this tool's word alone.

## Follow-ups

Paper index `0` is the first paper of the run.

| Job | Call |
|---|---|
| Re-query the failed databases of not-found refs | `POST /api/runs/{id}/papers/0/retry --json '{"scope":"failed"}'`, then the report call again |
| Re-check not-found refs / all problems / one ref | same, with `{"scope":"not_found"}` / `{"scope":"problems"}` / `{"scope":"ref","ref_idx":17}` |
| Report as Markdown | `GET '/api/runs/{id}/export?format=markdown&problematic=1' -o report.md` |
| Your past runs | `GET '/api/runs?limit=10'` |
| Which databases are on, and how fresh | `GET /api/options`, `GET /api/databases` |

A retry while the run is busy gets `409`. Give the user the run's page: the
tool's web address + `run.web_path`.

## Limits and rules

- An agent account may do what a `user` account does: submit papers, read
  and export its own runs, retry, cancel and delete them, mark a reference
  safe and set a paper's verdict. It may not manage accounts, tokens, keys,
  databases or settings (`403`). It sees only its own runs.
- Ask the user first before you mark a reference as a false positive
  (`PUT …/refs/{idx}/fp`): it also feeds the shared local corpus that later
  checks trust. Ask before `DELETE /api/runs/{id}`: it cannot be undone.
- Uploads: at most 500 files per run, and one call through `taskctl tool`
  holds at most 32 MB (base64 makes a PDF a third larger). `GET /api/options`
  has the server's limit and the accepted file types.
- Live event streams (`…/events`) do not work through the tunnel: poll the
  report with `?wait=` instead.
- Every call by an agent is in the audit log, with the account, method,
  path, status and address.
- Errors are JSON `{"error": "…"}`: `400` bad input · `401` bad or no token
  · `403` not allowed · `404` no such run, or not yours · `409` busy ·
  `429` rate limited (`Retry-After`).

## Endpoint reference

Every path is under the tool's base URL. Calls need an account: an agent or
API token (`Authorization: Bearer hallu_…`) or a person's browser session,
unless the endpoint says otherwise. A session needs the `X-CSRF-Token`
header on changes, except through the tunnel.

When the server has an end-to-end key (`GET /api/health` says
`"e2e": {"required": true}`), every call except `GET /api/health` goes
sealed through `POST /api/e2e`. A plain call gets
`400 {"detail": "…", "e2e": "required"}`. `taskctl tool` and the web pages
seal for you.

In the examples, `$T` is `taskctl tool hallucinator`.

## Reference: service

### GET /api/health

No account, always plain. Answers whether end-to-end encryption is on and
which key ids the server takes (current first, then the previous one during
a rotation).

```bash
curl -s http://HOST/api/health
# {"ok":true,"e2e":{"required":true,"kids":["1f112aa78ba5eef7"]}}
```

### POST /api/e2e

The end-to-end tunnel: Catelier E2E protocol version 1. The body is one
sealed request envelope (`Content-Type: application/vnd.catelier.e2e`); the
answer is `200` with one sealed response envelope that holds the real status,
headers and body. The protocol (keys `cek1_…`, envelope layout, test vectors)
is in Catelier's `server/catelier/e2e.py` and `server/tests/e2e_vectors.json`.

```bash
$T GET /api/agent/whoami      # taskctl seals it and posts it here
```

Errors, plain JSON `{"detail", "e2e": code}`: `400` with `bad_envelope`,
`unknown_kid` (another key), `stale` (clock off by more than 2 minutes),
`replay` (the same envelope twice) or `off` (no key on this server); `413`
too large; `429` `blocked` (too many envelopes from this address failed).

### GET /api/agent/guide

This guide as `text/markdown`. Any account. `?section=<slug>` returns one
`##` section (slugs: lowercase heading, other characters as `-`).

```bash
$T GET '/api/agent/guide?section=check-a-paper'
```

Errors: `404` unknown section (the message lists the slugs).

### GET /api/agent/whoami

The account that made the call. Any account.

```bash
$T GET /api/agent/whoami
# {"name":"Frieren","kind":"agent","role":"user"}
```

`kind` is `agent` or `person`; `role` is `user` or `admin`. Errors: `401`.

### GET /api/docs

The same guide, with no account needed (also at `/llms.txt`). With an
end-to-end key, it too comes only through the tunnel.

```bash
$T GET /api/docs
```

### GET /api/docs/reference

The full data contract (`API.md`): every field of runs, papers, references,
databases and jobs. No account needed.

```bash
$T GET /api/docs/reference
```

## Reference: account

### GET /api/auth/me

The signed-in account, its CSRF token for a session, and `bootstrap: true`
when no account exists yet. Without credentials it answers `200` with
`"user": null`; a bad token is `401`.

```bash
$T GET /api/auth/me
# {"user":{"id":7,"username":"Frieren","role":"user","kind":"agent",…},"auth":"token","csrf":null,"bootstrap":false}
```

### POST /api/auth/login

People only: sign in with a password and get the `hallu_session` cookie
(through the tunnel, the cookie comes back in the sealed reply). Agent
accounts have no password.

```bash
$T POST /api/auth/login --json '{"username":"alice","password":"…"}'
# {"user":{…}}  + Set-Cookie: hallu_session=…
```

Errors: `401` wrong name or password · `403` account disabled or another
origin · `429` locked after 5 failures, or the address after 20
(`retry_after`).

### POST /api/auth/logout

Session only: ends the session. `204`. Errors: `401`, `403` with a token.

### POST /api/auth/password

Session only: `{"current_password", "new_password"}` (10–256 characters).
Ends the account's other sessions. `204`. Errors: `400` wrong current
password or a weak new one · `403` with a token.

### GET /api/tokens

Session only: your API tokens (never the secrets).

```bash
$T GET /api/tokens
# {"tokens":[{"id":3,"name":"laptop","prefix":"hallu_AbCd","created_at":0,"expires_at":null,"last_used_at":0,"last_used_ip":"10.0.0.5",…}]}
```

Errors: `403` with a token (a token cannot manage tokens).

### POST /api/tokens

Session only: `{"name": "label", "expires_in_days": 90 | null}`. Returns the
secret once.

```bash
$T POST /api/tokens --json '{"name":"laptop","expires_in_days":90}'
# 201 {"token":{…},"secret":"hallu_…"}
```

Errors: `400` bad name, bad expiry or 50 tokens already · `403` with a token.

### DELETE /api/tokens/{id}

Session only: revoke one of your tokens (admins: anyone's). It stops working
at once. `204`. Errors: `404` · `403` with a token.

## Reference: runs

### GET /api/options

The databases you can turn off, their defaults and availability, the upload
limit and the accepted file types.

```bash
$T GET /api/options
# {"databases":[{"name":"CrossRef","enabled_by_default":true,"available":true,…}],"max_upload_mb":200,"accepted":[".pdf",…]}
```

### POST /api/runs

Start a check. Multipart: one or more `files` fields and an optional
`options` field (a JSON string). Or JSON:
`{"files": [{"name", "text" | "base64"}], "options": {…}}`.

`options`: `title` (shown in the history), `disabled_dbs` (names from
`/api/options`), `url_match` (also check web-page citations), `bib_mode`
(`merge`, the default, pairs a `.bib`/`.bbl` with the PDF of the same stem;
`separate` checks each file alone), `searxng`, `check_openalex_authors`.

```bash
$T POST /api/runs --json '{"files":[{"name":"refs.bib","text":"@article{a, title={…}, author={…}}"}],"options":{"title":"refs"}}'
$T POST /api/runs --data-file run.json     # {"files":[{"name":"paper.pdf","base64":"JVBERi0…"}]}
# 201 {"run_id":"9f2c…","links":{"report":"/api/runs/9f2c…/report","detail":"/api/runs/9f2c…","events":"/api/runs/9f2c…/events","web":"/#/runs/9f2c…"}}
```

Errors: `400` no file, an unsupported or empty file, bad base64, a PDF that
is not a PDF, bad options · `413` too large.

### GET /api/runs

Your runs, newest first. `?q=` search, `?status=`, `?limit=` (≤ 200),
`?offset=`; admins may add `?all=1`.

```bash
$T GET '/api/runs?limit=10'
# {"total":12,"runs":[{"id":"9f2c…","title":"paper v3","status":"done","stats":{…},…}]}
```

### GET /api/runs/{id}

Everything about a run: every paper and reference with per-database results.
Large. `?wait=<secs>` (≤ 600) first waits for the run to finish.

```bash
$T GET '/api/runs/9f2c…?wait=0'
# {"run":{…,"options":{…}},"papers":[{"idx":0,"refs":[{"idx":0,"verdict":"verified","result":{…}},…]}]}
```

Errors: `404` no such run, or not yours.

### DELETE /api/runs/{id}

Delete a run (it is cancelled first). Cannot be undone. `204`. Errors: `404`.

### GET /api/runs/{id}/events

A Server-Sent Events stream of the run's progress: `snapshot`, then `run`,
`paper`, `refs`, `ref`, `db`, `notice` and `end`. For browsers on a plain
connection; through the tunnel it answers `406`. Poll `GET /api/runs/{id}`
or the report instead.

### GET /api/runs/{id}/report

The compact report for scripts and agents (about 1 KB). `?wait=<secs>`
(≤ 600) waits for the run to finish; `?refs=problems` (default), `all` or
`none`.

```bash
$T GET '/api/runs/9f2c…/report?wait=100&refs=problems'
$T GET '/api/runs/9f2c…/report?wait=540' --timeout 600
# {"run":{"done":true,"summary":"…","needs_attention":2,…},"papers":[{"refs":[…]}]}
```

Errors: `404`.

### POST /api/runs/{id}/cancel

Stop a queued or running run. `204`. Errors: `404`.

### GET /api/runs/{id}/export

The report as a file. `?format=json|csv|markdown|text|html`, `?paper=<idx>`
(default: every paper), `?problematic=1` (only references with problems).

```bash
$T GET '/api/runs/9f2c…/export?format=markdown&problematic=1' -o report.md
```

Errors: `400` unknown format · `404` no such run or paper.

### POST /api/runs/{id}/papers/{pidx}/retry

Check references again. `{"scope": "failed"}` re-queries only the databases
that failed for not-found references; `not_found` and `problems` re-check
fully; `{"scope": "ref", "ref_idx": 17}` re-checks one.

```bash
$T POST /api/runs/9f2c…/papers/0/retry --json '{"scope":"failed"}'
# 202 {"queued":3}
```

Errors: `404` no such run, paper or reference · `409` the run is busy.

### PUT /api/runs/{id}/papers/{pidx}/verdict

Set a paper's review verdict: `{"verdict": "safe" | "questionable" | null}`.
`204`. Errors: `400` unknown verdict · `404`.

### PUT /api/runs/{id}/papers/{pidx}/refs/{ridx}/fp

Mark a reference as a false positive (or `null` to clear). Reasons:
`broken_parse`, `exists_elsewhere`, `all_timed_out`, `known_good`,
`non_academic`. It also feeds the shared local corpus: ask the user first.

```bash
$T PUT /api/runs/9f2c…/papers/0/refs/17/fp --json '{"reason":"known_good"}'
# {"ref":{…},"stats":{…}}
```

Errors: `400` unknown reason · `404`.

## Reference: databases

### GET /api/databases

The offline databases: build date, age, size, record counts and running jobs.
People who are not admins and agents see no server paths.

```bash
$T GET /api/databases
# {"databases":[{"key":"dblp","label":"DBLP","age_days":12,"stale":false,…}],…}
```

### POST /api/databases/{key}/update

Admin only: rebuild an offline database. `{"params": {…}}` as listed under
`update.params`. `202 {"job": {…}}`. Errors: `400` · `403` · `409` a job is
running.

### POST /api/databases/corpus/import

Admin only: import a venue into the local corpus,
`{"venue", "source_tag", "url" | "pdf_path"}`. `202 {"job": {…}}`. Errors:
`400` · `403` · `409`.

### POST /api/databases/corpus/import-marked-safe

Admin only: import every reference marked safe into the local corpus.
`202 {"job": {…}}`. Errors: `403` · `409`.

### POST /api/databases/cache/clear

Admin only: clear the query cache, `{"not_found_only": true}` for only the
not-found entries. `{"removed": N}`. Errors: `403`.

### GET /api/jobs

Recent database jobs (`?limit=`). Not admins: no server paths.

```bash
$T GET '/api/jobs?limit=5'
# {"jobs":[{"id":"…","db_key":"dblp","status":"succeeded",…}]}
```

### GET /api/jobs/{id}

Admin only: a job and its full log. Errors: `403` · `404`.

### GET /api/jobs/{id}/events

Admin only: the job's log as Server-Sent Events. Through the tunnel it
answers `406`; poll `GET /api/jobs/{id}` instead.

### POST /api/jobs/{id}/cancel

Admin only: stop a job. `204`. Errors: `403` · `404`.

## Reference: admin

Admin only (a person with role `admin`; agent accounts never are). Others get
`403`.

### GET /api/admin/users

Every account, with `kind`, lockout state and run count.

```bash
$T GET /api/admin/users
# {"users":[{"id":7,"username":"Frieren","role":"user","kind":"agent","status":"active","run_count":3,…}]}
```

### POST /api/admin/users

Create a person's account: `{"username", "password", "role": "user" | "admin"}`.
`201 {"user": {…}}`. Agent accounts are made on the server with
`hallucinator-webapp agent add <Name>`. Errors: `400` · `409` name taken.

### PATCH /api/admin/users/{id}

`{"status": "active" | "disabled", "role": "admin" | "user", "unlock": true}`
(any of them). `{"user": {…}}`. Errors: `400` (an agent cannot be an admin;
keep one active admin) · `404`.

### DELETE /api/admin/users/{id}

Delete an account and its runs. `204`. Errors: `400` (yourself, or the last
admin) · `404`.

### GET /api/admin/tokens

Every account's API tokens (never the secrets). Agent tokens are issued,
rotated and revoked on the server with `hallucinator-webapp agent
issue|rotate|revoke <Name>`.

### GET /api/admin/auth-events

Sign-in activity (`?limit=`, ≤ 1000) and blocked addresses.

```bash
$T GET '/api/admin/auth-events?limit=50'
# {"events":[{"at":0,"ip":"…","username":"alice","kind":"login_ok",…}],"blocked_ips":[…]}
```

### GET /api/admin/audit

The audit log: every call by an agent, and every call by anyone that
changes data (sign-ins and token changes too). Kept 90 days. Filters:
`?account=<name>`, `?kind=agent|person`, `?limit=` (≤ 1000), `?before=<id>`
(the `next_before` of the previous page).

```bash
$T GET '/api/admin/audit?kind=agent&account=Frieren&limit=20'
# {"entries":[{"id":81,"at":0,"username":"Frieren","kind":"agent","method":"GET","path":"/api/runs/9f2c…/report","status":200,"ip":"10.0.0.5","via":"token","sealed":true}],"next_before":null,"retention_days":90}
```

Errors: `400` unknown kind · `403`.

### DELETE /api/admin/ip-blocks/{ip}

Lift a sign-in block of an address early. `204`. Errors: `403`.
