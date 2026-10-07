# Fork notes

This repository is a fork of
[gianlucasb/hallucinator](https://github.com/gianlucasb/hallucinator). Fork
additions are kept apart from upstream code so `git merge upstream/main`
stays conflict-free.

## New features

- **Web interface** (`hallucinator-webapp`): upload PDFs, `.bib`/`.bbl`,
  GROBID `.xml` or `.zip`/`.tar.gz` archives and watch every reference being
  checked live, per paper and per database. It uses the same engine and
  config as the CLI/TUI.
- **Accounts with brute-force protection**: no self sign-up; administrators
  create accounts (Admin page or `create-user`). An account locks after 5
  failed sign-ins, longer on repeats, and unknown usernames lock the same
  way. An IP is blocked after 20 failures.
- **PDF + `.bib` merging**: the PDF decides which references are cited, and
  the `.bib` fills in the titles, authors, DOIs and URLs the PDF parser
  missed. `.bib`/`.bbl` entries now keep their URLs, so the URL fallback works
  for them.
- **Check history**: runs, papers and results are stored in SQLite as they
  arrive. Users can review them, mark false positives, re-check and export in
  every upstream format.
- **Reference-database page**: shows each offline DB's build date, age, size
  and record counts. Admins can update DBs and grow the local corpus with a
  live log. Paths and logs are admin-only.

## Changed files

| Path | What | Upstream overlap |
|---|---|---|
| `hallucinator-rs/crates/hallucinator-webapp/` | Multi-user web interface: accounts with brute-force protection, check history in SQLite, PDF + `.bib` merging, reference-database management page. See its [README](hallucinator-rs/crates/hallucinator-webapp/README.md) and [API.md](hallucinator-rs/crates/hallucinator-webapp/API.md). | none — own Cargo workspace and lock file |
| `hallucinator-rs/crates/hallucinator-bbl/src/lib.rs` | `.bib`/`.bbl` references now carry their URLs (`bib_entry_urls`, `extract_urls`), so web citations from bibliographies can use the URL fallback. | small patch — candidate for an upstream PR |
| `FORK.md` | this file | none |

## Syncing with upstream

```bash
git remote add upstream https://github.com/gianlucasb/hallucinator.git   # once
git fetch upstream && git merge upstream/main
cd hallucinator-rs && cargo build --release -p hallucinator-cli
cd crates/hallucinator-webapp && cargo test && cargo build --release
```

The webapp's README lists the few upstream changes that need a matching
edit here (e.g. a new database backend name).
