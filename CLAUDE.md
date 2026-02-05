# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Winbindex is a Windows binaries search and download index. It scrapes Windows update metadata from Microsoft, indexes PE files (exe, dll, sys), and serves a searchable static website via GitHub Pages. The database lives on the `gh-pages` branch; the `main` branch has the website code and Python data pipeline.

## Commands

### Lint JavaScript
```bash
npx eslint .
```

### Run the data pipeline (requires Windows + tools in data/tools/)
```bash
cd data
python -u deploy.py
```

Individual pipeline stages can be run separately:
```bash
python -u upd01_get_list_of_updates.py
python -u upd02_get_manifests_from_updates.py
python -u upd03_parse_manifests.py
python -u upd04_get_virustotal_data.py
python -u upd05_group_by_filename.py
python -u symbol_server_link_enumerate.py
```

There are no tests.

## Architecture

### Frontend (static site, no build step)
- `index.html` + `winbindex.js` + `winbindex.css` — single-page app
- Third-party libraries in `modules/` (jQuery, Bootstrap 4, DataTables, pako, etc.)
- User selects a filename → `filenames.json` loaded → per-file `.json.gz` fetched from gh-pages → decompressed in browser with pako → rendered via DataTables
- **JavaScript must target ES5/IE11** — ESLint enforces this via `ecmaVersion: 5` and `eslint-plugin-compat` with browserslist `ie 11`

### Data Pipeline (Python, `data/` directory)
Orchestrated by `deploy.py`, which processes one KB update at a time:

1. `upd01` — Scrapes Microsoft support pages for Windows update KB list → `updates.json`, `info_sources.json`
2. `upd02` — Downloads update manifests from Microsoft Catalog → `manifests/`
3. `upd03` — Parses manifest XML, extracts PE metadata and hashes → `parsed/`
4. `upd04` — Fetches VirusTotal data via rotating Tor proxies (pymultitor) → `virustotal/`
5. `upd05` — Aggregates everything, groups by filename, gzip-compresses with ISA-L → `by_filename_compressed/`, `filenames.json`
6. `symbol_server_link_enumerate` — Validates download links on Microsoft's symbol server (64 concurrent threads)

See `data/README.md` for the pipeline flow diagram.

### Configuration
- `data/config.py` — Central config: unsupported updates, architecture (`x64`), hash exceptions, compression level, multiprocessing settings
- Output path controlled by `.out_path_override` file (used in CI to point at checked-out gh-pages)

### CI/CD (GitHub Actions, Windows runners)
- `deploy.yml` — Runs daily (7:00 AM UTC) + Tuesdays (6:15 PM UTC). Checks out gh-pages into `data/gh-pages/`, runs `deploy.py`, commits and pushes results
- `maintenance.yml` — Monthly: squashes old commits (gh-pages history grows large), updates metadata
- Pipeline respects GitHub Actions' 6-hour limit, stopping 10 minutes before

### Data Storage
- `main` branch: website code + Python scripts
- `gh-pages` branch: `by_filename_compressed/*.json.gz` (one per binary name), `filenames.json`, `updates.json`, `info_sources.json`
- Incremental updates tracked via `updates_last.json` — only new KBs are processed

## Key Constraints

- Frontend JS: ES5 only, 4-space indentation, strict mode required, no undefined variables
- Python data scripts require Windows (PE tools: `sigcheck64.exe`, `PSFExtractor.exe`, `msdelta.dll`, `sxsexp64.exe` in `data/tools/`)
- Python dependencies: `isal`, `mitmproxy`, `orjson`, `pymultitor`, `requests`, `signify` (listed in `.github/requirements.txt`)
