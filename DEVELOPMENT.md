# Development

## Setup

```bash
poetry install                 # app + dev tools; the virtualenv lives in ~/.cache/pypoetry
cp .env.example .env           # set SECRET_KEY, APP_ENV=development
poetry run python src/manage.py init-db
poetry run python src/manage.py create-invite
poetry run python -m src.app   # http://localhost:5000, debug mode
```

## Checks

```bash
poetry run pytest              # test suite (in-memory database, temporary data folder)
poetry run pytest --cov        # with coverage report
poetry run ruff check          # lint (pycodestyle, pyflakes, import order, bugbear, pyupgrade)
poetry run ruff format         # format
poetry run mypy src            # type check
```

- The test that compares the browser's key derivation with the Python version needs `node`; it's skipped otherwise
- All tool caches and coverage data are kept in `~/.cache`, not in the project (it lives in a synced folder). pytest's own cache is disabled for the same reason

## Container

- `Dockerfile` (two stages), `docker/entrypoint.sh` (ownership, generated `SECRET_KEY`, database setup, first invite), `docker/run_as.py` (drops root to `PUID:PGID`), `docker/manage` (management commands as that user), `docker/gunicorn.conf.py` (server defaults)
- Unraid template: `unraid/secure-media-gallery.xml`. CI/publishing: `.github/workflows/docker-publish.yml`. 

## Dependencies

- Dependabot (`.github/dependabot.yml`) opens weekly PRs for Python packages (minor and patch updates grouped), the Docker base image and GitHub Actions, and security PRs as soon as an advisory appears. The workflow runs the tests on every PR
- Not covered by Dependabot: the vendored Argon2 library in `src/static/vendor/hash-wasm/` (see `SOURCE.txt` for version and checksum) and `POETRY_VERSION` in the `Dockerfile`; check these by hand now and then
- Manual audit: `poetry run pip freeze > /tmp/req.txt && pipx run pip-audit -r /tmp/req.txt --no-deps --disable-pip`

## Layout and conventions

- All application code is in `src/`: `app.py` (factory), `routes.py`, `models.py`, `security.py`, `config.py`
- Templates in `src/templates/`, static files in `src/static/`; reference static files with `asset_url('path')` (adds a content hash for caching)
- Every `<form method="POST">` needs `<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">` (a test checks this). `fetch()` calls get the `X-CSRFToken` header automatically (wrapper in `e2e-encryption.js`)
- Inline `<script>` tags need `nonce="{{ csp_nonce }}"`; inline event handlers (`onclick=` etc.) are blocked by the Content-Security-Policy. Use `addEventListener`, and `data-confirm="…"` on forms for confirmation dialogs
- Colours are CSS variables defined in `src/static/css/app.css` (a light set in `:root`, a dark set in `:root[data-theme="dark"]`). Don't hard-code colours in page styles; add a variable to both sets instead
- The service worker (`src/static/js/sw.js`) only caches static files with a `?v=` content hash. Never let it cache pages, API responses or media. It also serves `/__stream/<token>/<name>`: decrypted byte ranges of a file (video playback, downloads)
- The chunked file format lives in `src/static/js/chunked-file.js`, shared by the pages and the service worker (`importScripts`). Changing it changes the stored file format
- Upload chunks are sent as `Blob` bodies on purpose: Chromium keeps `fetch()` `ArrayBuffer` bodies in memory (a 1.5 GB upload grew the tab by 1.5 GB)
- Testing notes: headless Chromium cancels every download answered by a service worker (even a plain-text one), so test downloads in a normal browser window. Playwright's network tracking keeps copies of request bodies, which distorts memory measurements of uploads
- Fingerprint unlock (`DeviceUnlock` in `e2e-encryption.js`) is browser-only. Test it in Chromium with a virtual authenticator (DevTools protocol `WebAuthn.addVirtualAuthenticator` with `hasPrf: true`). Note: after one failed user verification, Chromium's virtual authenticator keeps refusing even when switched back, so run such a test last
- The key derivation exists twice and must stay identical: `src/static/js/e2e-encryption.js` (`deriveAccountKeys`) and `src/security.py` (`derive_account_keys`). A test checks this
- No database migrations before the first production release: after model changes, empty `DATA_DIR` and run `init-db`

## Ideas

- [ ] Keep the unlocked private key as a non-extractable key in IndexedDB instead of caching the wrap key in sessionStorage
- [ ] Per-user storage quotas and a per-upload file count limit
- [ ] Two-factor authentication
- [ ] Batch download of albums
