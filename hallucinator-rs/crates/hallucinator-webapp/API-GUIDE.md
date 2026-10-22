# Hallucinator API guide (for scripts and agents)

Hallucinator checks every reference of an academic paper against CrossRef,
arXiv, DBLP, Semantic Scholar, OpenAlex, PubMed, ACL Anthology and more, and
flags references that cannot be found (possible fabrications), whose authors,
DOI or arXiv id do not match, or that were retracted.

- Base URL: `{{BASE_URL}}`
- This guide: `GET /api/docs` (also `/llms.txt`). Full contract with every
  field: `GET /api/docs/reference`. Both are public.
- Everything else needs an API token.

If your shell sets `http_proxy`, bypass it for this host
(`curl --noproxy '*'`), otherwise the proxy answers instead of the server.

## 1. Authenticate

Send a personal API token on every request:

```
Authorization: Bearer hallu_…
```

Create one on the web interface (**Account → API tokens**), or an
administrator runs `hallucinator-webapp create-token --username <u> --name <label>`
on the server. A token acts with its account's permissions and needs no CSRF
header. It cannot sign out, change the password or manage tokens.

Check it:

```bash
curl -s -H "Authorization: Bearer $HALLU_TOKEN" {{BASE_URL}}/api/auth/me
# {"auth":"token","user":{"username":"agent","role":"user",...},...}
```

`401` means the token is missing, wrong, expired or revoked.

## 2. Check a paper: submit, then wait for the report

```bash
# Submit: one or more files in the multipart field "files".
curl -s -H "Authorization: Bearer $HALLU_TOKEN" \
  -F "files=@paper.pdf" \
  {{BASE_URL}}/api/runs
# 201 {"run_id":"9f2c…","links":{"report":"/api/runs/9f2c…/report",...}}

# Wait up to 120 s for it to finish, then get the compact report.
curl -s -H "Authorization: Bearer $HALLU_TOKEN" \
  "{{BASE_URL}}/api/runs/9f2c…/report?wait=120"
```

Repeat the report call until `run.done` is `true`; `wait` is capped at
600 s. Most references are checked within seconds, but references that are
not found are retried while rate-limited databases (e.g. Semantic Scholar
without an API key) back off, so a 50-reference paper takes from under a
minute to about 7 minutes. Runs queue when the server is busy. Poll the
report meanwhile (`wait=0`) to see partial results.

### Inputs

| File | What is checked |
|---|---|
| `.pdf` | the reference list parsed from the PDF |
| `.bib` / `.bbl` | every entry (alone), or merged with a PDF of the same file stem |
| `.xml` | GROBID TEI output |
| `.zip`, `.tar.gz` | every file above inside the archive |

To check references you already have as text, write them to a `.bib` file
(or pipe it: `-F "files=@-;filename=refs.bib" < refs.bib`).

A `.bib` uploaded with a PDF of the same stem (or as the only PDF + `.bib`
pair) is merged: the PDF decides which references are cited and the `.bib`
supplies clean titles, authors, DOIs and URLs. That gives the best results
for your own paper.

Optional field `options` (a JSON string):

```bash
-F 'options={"title":"my paper v3","disabled_dbs":["Open Library"],"url_match":true,"bib_mode":"merge"}'
```

- `title`: name shown in the history (default: the file name).
- `disabled_dbs`: databases to skip. `GET /api/options` lists them with
  their defaults and availability.
- `url_match`: also check web-page citations (URL liveness / Wayback).
  Without it, a not-found reference that cites a non-academic URL is
  reported as `skipped`.
- `bib_mode`: `merge` (default) or `separate` (check every file on its own).

## 3. Read the report

`GET /api/runs/{id}/report?wait=<secs>&refs=problems|all|none`

```json
{
  "run": {
    "id": "9f2c…", "title": "paper.pdf", "status": "done", "done": true,
    "stats": {"total": 48, "verified": 41, "not_found": 2, "mismatch": 1, "inconclusive": 1, "skipped": 3, "...": 0},
    "needs_attention": 4,
    "summary": "Run done: 48 references, 41 verified, 2 not found, 1 mismatched, 1 inconclusive, 0 retracted, 3 skipped. Needing attention: 4.",
    "web_path": "/#/runs/9f2c…"
  },
  "papers": [{
    "idx": 0, "filename": "paper.pdf", "status": "done", "stats": {"...": 0},
    "refs": [{
      "idx": 17, "number": 18, "verdict": "not_found", "needs_attention": true,
      "reason": "Not found in any database: possibly fabricated, or a source the databases do not index.",
      "title": "…", "authors": ["…"], "raw_citation": "[18] …"
    }]
  }]
}
```

- `refs=problems` (default) lists only references that need attention:
  `not_found`, `mismatch`, `inconclusive` or retracted, and not marked safe.
  `refs=all` lists every reference; `refs=none` only the counters.
- Empty and `null` fields are omitted. Other fields that may appear:
  `doi`, `arxiv_id`, `urls`, `mismatch` (`author`, `doi`, `arxiv_id`),
  `source` (the database that matched), `found_authors`, `paper_url`,
  `failed_dbs`, `retracted`, `fp_reason`, `skip_reason`.
- `number` is the reference's number in the paper; `idx` is what the API
  uses in URLs (`/papers/{paper idx}/refs/{idx}`).
- Show the user `{{BASE_URL}}` + `web_path` to review a run in the browser.

### Verdicts

| `verdict` | Meaning | What to do |
|---|---|---|
| `verified` | Found, authors match | nothing |
| `not_found` | No database has it | strongest fabrication signal, but also books, theses, standards, very new or non-English work; search the web before concluding |
| `mismatch` | Title found, but authors / DOI / arXiv id differ | compare `found_authors` / `paper_url` with the citation |
| `inconclusive` | Not found while some databases failed (`failed_dbs`) | retry (below), then judge |
| `skipped` | Not checked: unparseable citation, short title, URL-only, or a web page without `url_match` | read `reason`; check by hand if it matters |
| `pending` | Not checked yet | wait |

`retracted: true` can come with any verdict: the cited paper was retracted.

A `not_found` result is evidence, not proof. Report it as "could not be
verified", with the reason, and let a person decide.

## 4. Follow-ups

All take the token; none need a CSRF header.

| Task | Call |
|---|---|
| Re-query the failed databases of not-found refs | `POST /api/runs/{id}/papers/{pidx}/retry` `{"scope":"failed"}` |
| Re-check not-found / all problems / one ref | same, `{"scope":"not_found"}` / `{"scope":"problems"}` / `{"scope":"ref","ref_idx":17}` |
| Mark a reference as a false positive | `PUT /api/runs/{id}/papers/{pidx}/refs/{idx}/fp` `{"reason":"known_good"}` (or `null` to clear) |
| Report as a file | `GET /api/runs/{id}/export?format=markdown&problematic=1` (also `json`, `csv`, `text`, `html`) |
| Your past runs | `GET /api/runs?limit=20&q=<search>` |
| Everything, including per-database results | `GET /api/runs/{id}?wait=<secs>` (large) |
| Live progress (SSE) | `GET /api/runs/{id}/events` (`curl -N`) |
| Cancel / delete | `POST /api/runs/{id}/cancel` / `DELETE /api/runs/{id}` |
| Databases and their freshness | `GET /api/databases` |

A retry answers `202 {"queued": N}` (`409` while the run is still busy);
then wait on the report again. `fp` reasons: `broken_parse`,
`exists_elsewhere`, `all_timed_out`, `known_good`, `non_academic`.

## 5. Errors and limits

- Errors are JSON: `{"error": "human readable message"}`.
- `400` bad input · `401` bad token · `403` not allowed (e.g. an admin-only
  call) · `404` no such run or not yours · `409` busy · `429` rate limited
  (`Retry-After` header).
- Uploads: up to 200 MB and 500 files per run (`GET /api/options` has the
  current limit and accepted extensions).
- Each account sees only its own runs; administrators see everyone's
  (`GET /api/runs?all=1`).
