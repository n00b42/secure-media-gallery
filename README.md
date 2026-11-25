# 🔐 Secure Media Gallery

A privacy-focused web application for storing and sharing pictures and videos. Media is encrypted
in the browser before upload; the server only ever stores ciphertext and can't see your files,
their names or your password.

## Features

- **End-to-end encryption**: files, file names and video thumbnails are encrypted in the browser (AES-GCM, one key per file)
- **One password**: the password never leaves the browser; it unlocks your encryption key in any browser
- **Fingerprint / face unlock** per device (passkey with the PRF extension), as an alternative to typing the password
- **Albums and selective sharing**: create, rename and share albums with specific users; revoke access at any time
- **Key fingerprints**: verify the people you share with, to detect key substitution
- **Images and videos of any size**: JPG, PNG, GIF, BMP, WebP, MP4, AVI, MOV, MKV, WebM. Files are encrypted and uploaded in 4 MB pieces with a progress bar; interrupted uploads resume where they stopped
- **Streaming playback**: videos start immediately and can be seeked, even multi-GB files; nothing is decrypted to disk
- **Download**: every file can be downloaded decrypted, under its original name, streamed straight to disk
- **Invite-only registration**, rate-limited login, strict Content-Security-Policy
- **Light and dark theme** (automatic or chosen with the 🌓 button), full-width photo grid
- **Installable app (PWA)** on phones and desktops; needs HTTPS (or `localhost`)

## Quick start (local)

Requirements: Python 3.12+ and [Poetry](https://python-poetry.org/) 2.x.

```bash
git clone https://github.com/n00b42/secure-media-gallery.git
cd secure-media-gallery
./deploy.sh        # installs dependencies, creates .env with a generated SECRET_KEY, initializes the database
```

For local testing over `http://localhost`, set `APP_ENV=development` in `.env` (allows session cookies over HTTP). Then:

```bash
poetry run python src/manage.py create-invite     # invite key for the first account
poetry run python -m src.app                      # http://localhost:5000
```

Open `http://localhost:5000`, register with the invite key, create an album and upload files.

## Configuration

Settings are read from the environment and from `.env` in the project root.

| Variable | Default | Purpose |
|---|---|---|
| `SECRET_KEY` | *(required for local runs)* | Signs session cookies; ≥ 32 characters. `./deploy.sh` generates it; the container generates one on first start if unset (kept in `/data/.secret_key`) |
| `APP_ENV` | `production` | `development` enables debug mode and session cookies over HTTP |
| `DATA_DIR` | `run` | Folder for `secure_gallery.db` and `uploads/`. Relative paths are resolved from the project root. Docker uses `/data` |
| `TRUSTED_PROXY_COUNT` | `0` | Number of reverse proxies in front of the app. Must be right for the login rate limiting; see *Behind an HTTPS reverse proxy* |
| `SESSION_COOKIE_SECURE` | `true` | Set to `false` only to test the production build over `http://localhost` |
| `MAX_FILE_SIZE` | `0` (unlimited) | Largest single file. Sizes accept `500M`, `20G`, `1T` or bytes |
| `USER_STORAGE_QUOTA` | `0` (unlimited) | Storage per user: everything in the albums they own, including files other members uploaded there and unfinished uploads |
| `MIN_FREE_DISK_SPACE` | `1G` | Uploads that would leave less free disk space are refused |
| `UPLOAD_EXPIRY_HOURS` | `168` | How long an unfinished upload can be resumed before it is deleted |
| `ALBUM_OVERVIEW_THUMBNAILS_ENABLED` | `true` | Show decrypted previews on dashboard album cards |
| `PUID` / `PGID` | `1000` / `1000` | Container only: owner of `/data` (Unraid: `99` / `100`) |
| `GUNICORN_CMD_ARGS` | *(empty)* | Container only: extra gunicorn options, e.g. `--workers 4 --threads 8` |
| `LOGIN_IP_MAX_FAILURES`, `LOGIN_USER_MAX_FAILURES`, `REGISTER_IP_MAX_FAILURES` (+ `_WINDOW_SECONDS`) | 20 / 10 / 10 | Rate limits for failed attempts (see `src/config.py`) |
| `SHARE_LOOKUP_MAX_FAILURES` (+ `_WINDOW_SECONDS`) | 20 per hour | Unsuccessful username lookups on the share form, per user |
| `SESSION_IDLE_TIMEOUT_MINUTES` | `120` | Sign out after this long without any request (an open page that is uploading or playing video counts as active) |

Logins expire 24 hours after login, or after 2 hours without activity. Every login is a server-side session: the *Account* page lists signed-in devices and can sign any of them out immediately.

## Management commands

```bash
poetry run python src/manage.py help
```

| Command | Purpose |
|---|---|
| `init-db` | Create the data folder and database tables |
| `create-invite [count]` | Generate invite keys for registration |
| `create-user <username>` | Create a user (password is prompted; keys are generated at first login) |
| `list-users`, `stats` | Show users / counts and storage used per album owner |
| `cleanup-orphans [--delete]` | Report (or delete) upload files without a database row and expired unfinished uploads |
| `drop-db` | Delete **all** data: tables and encrypted uploads |

## Security model

### Encryption
- **Files**: each file gets a random AES-256-GCM key in the browser. The file, its original name and (for videos) a preview thumbnail are encrypted with it
- **Chunked format**: the file is split into 4 MiB pieces, each encrypted separately with IV = random 8-byte nonce ‖ chunk number, and the chunk number plus a "last chunk" flag as authenticated data. Reordering, swapping or cutting off pieces is detected. Because pieces are independent, the service worker can decrypt any part of a file on its own: this enables streaming, seeking and downloads without loading the whole file into memory
- **File keys**: encrypted with the RSA-OAEP-4096 public key of every album member and stored on the server
- **Private keys**: stored on the server only as ciphertext, encrypted with a key derived from the password in the browser
- **Visible to the server**: whether a file is an image or a video, the ciphertext size (≈ file size), who uploaded it and the upload time. Nothing else

### Authentication
- The browser stretches the password with **Argon2id** (64 MiB memory, 3 passes, salted with the username; [hash-wasm](https://github.com/Daninet/hash-wasm), vendored in `src/static/vendor/`). Being memory-hard, it makes password guessing on GPUs much more expensive than PBKDF2. It runs only at login, registration, the unlock prompt and password change (well under a second on a desktop, longer on phones). The result is split with HKDF into an **auth key** (sent to the server, which stores only a scrypt hash of it) and a **wrap key** (never leaves the browser; decrypts the private key)
- Minimum password length is 8, enforced in the browser (the server never sees the password)
- Registration requires an invite key. Login and registration are rate limited per IP and per username; unknown usernames and wrong passwords get identical responses
- Every state-changing request (forms, JSON and upload APIs, logout) needs the session's CSRF token; session cookies are additionally `SameSite=Lax`, `HttpOnly` and `Secure`. Logins expire after 24 hours, or after 2 hours without activity
- Sessions are stored on the server (the cookie only carries a random token, the database only its hash). Logging out, "Sign out" on the *Account* page and a password change end sessions immediately, even if a cookie was copied
- **Password change** on the *Account* page happens in the browser: the private key is re-encrypted with the new password, so all files stay readable. All other devices are signed out, and fingerprint unlock must be set up again. There is no password *reset*: without the password the private key, and therefore the files, can't be decrypted
- Strict Content-Security-Policy with per-request script nonces, plus `X-Frame-Options`, `nosniff`, `Referrer-Policy`, `Permissions-Policy` and HSTS (on HTTPS). Fonts are self-hosted

### Fingerprint unlock (per device, optional)
- Enabled on the *Account* page after confirming the password. It creates a passkey on the device's built-in authenticator (fingerprint, face or device PIN)
- Each successful check makes the authenticator return a secret (WebAuthn PRF extension). The browser derives a key from it and encrypts the **auth key** and **wrap key** with it. The encrypted data stays in that browser's local storage; the server isn't involved and learns nothing new
- Fingerprint sign-in then performs a normal login with the auth key (same rate limits), and the unlock prompt uses the wrap key. The password always works as a fallback
- Anyone who can pass the device's fingerprint/face/PIN check can open the gallery on that device, like a saved password. Remove it on the *Account* page before giving a device away
- Requires HTTPS (or `localhost`) and a browser with PRF support: current Chrome/Edge (desktop and Android), Safari 18+ on iOS/macOS, Firefox 135+. Without a built-in authenticator the Keys page says it's not available

### Access control and revocation
- Public keys (needed to share) are only given out for users you share at least one album with, so user IDs can't be used to list all accounts. The share form reveals whether a username exists; unsuccessful lookups are rate limited
- Only the owner and the users an album is shared with can list it, download its encrypted files and fetch file keys
- Removing a user immediately blocks all of that and deletes their stored file keys. Files or keys they downloaded *before* removal can't be recalled; no end-to-end encrypted system can do that

### Fingerprints
The *Account* page shows the fingerprints of your key and of everyone you share albums with. Compare them through another channel (in person, phone, messenger). If they match, nobody has swapped a key.

### Limitations
- The server delivers the JavaScript that performs the encryption. Someone who controls the server could serve modified code. This design protects against database or disk theft and an honest-but-curious operator, not against an actively malicious server
- Browsers only provide the encryption API (WebCrypto) on HTTPS or `http://localhost` / `127.0.0.1`

## Deployment

### Docker

The image is published to `ghcr.io/n00b42/secure-media-gallery` (see *Publishing the image*).

```bash
cp .env.example .env     # optional: TRUSTED_PROXY_COUNT=1 behind a proxy, limits, …
docker compose up -d     # or: docker compose up -d --build   to build locally
docker compose logs web  # first start: shows an invite key for the first account
docker compose exec web manage create-invite
```

- The container listens on `127.0.0.1:5000` only, so it's meant to sit behind an HTTPS reverse proxy
- All data lives in `/data` (the `gallery-data` volume): database, encrypted uploads and, if `SECRET_KEY` isn't set, a generated key (`/data/.secret_key`)
- The container starts as root only to give `/data` to `PUID:PGID` (default 1000:1000), then runs everything as that user. Use `manage <command>` for management commands; it runs as that user too
- Server tuning without rebuilding: `GUNICORN_CMD_ARGS="--workers 4 --threads 8"`

### Unraid

The template `unraid/secure-media-gallery.xml` shows all settings in Unraid's container form, marked required or optional:

| Shown | Setting |
|---|---|
| required | Data folder (`/mnt/user/appdata/secure-media-gallery`), HTTP port (`5000`), trusted proxies (`1`) |
| optional | Secret key (generated if empty), max file size, storage quota |
| advanced | PUID/PGID (99/100), free-space reserve, upload expiry, album previews, server tuning, secure cookies |

Install:
1. Copy the template to the flash drive: `/boot/config/plugins/dockerMan/templates-user/my-secure-media-gallery.xml` (e.g. `wget -O … https://raw.githubusercontent.com/n00b42/secure-media-gallery/main/unraid/secure-media-gallery.xml` in the Unraid terminal)
2. *Docker → Add Container → Template:* pick *secure-media-gallery*, adjust the port if 5000 is taken, apply
3. Point your HTTPS reverse proxy at `http://<unraid-ip>:<port>` and check the requirements in the next section
4. Open the container log: it shows the invite key for the first account. More invite keys: container console → `manage create-invite`

### Behind an HTTPS reverse proxy

The app itself serves plain HTTP; HTTPS is the job of a reverse proxy you choose (nginx, Nginx Proxy Manager, SWAG, Traefik, Caddy, Cloudflare Tunnel, …). HTTPS is mandatory: browsers only provide the encryption API on HTTPS pages (or `http://localhost`).

**Requirements, so login rate limiting works.** Failed logins and registrations are limited per client IP (and per username). Behind a proxy the app only sees the proxy's IP, unless all of the following hold:

1. **The proxy sends `X-Forwarded-For`** with the client's IP appended, and **`X-Forwarded-Proto`** (`https`). Most proxies do this by default (Traefik, Caddy, Nginx Proxy Manager, SWAG); plain nginx needs the two `proxy_set_header` lines below
2. **`TRUSTED_PROXY_COUNT` = number of proxies** between the browser and the app: `1` for a single proxy, `2` for e.g. Cloudflare's proxy plus your own, `0` without a proxy. The app takes the client IP from that many entries from the end of `X-Forwarded-For`
   - too low (e.g. `0` behind a proxy): every user has the proxy's IP, so the per-IP limits are shared: one attacker locks everyone out for 15 minutes
   - too high: the app trusts addresses the client wrote into the header itself, so an attacker can make up a new IP for each attempt
3. **Only the proxy can reach the app's port.** Anyone who can connect to the port directly can send a fake `X-Forwarded-For` and evade the per-IP limit. Bind the port to `127.0.0.1` if the proxy is on the same host (as `docker-compose.yml` does), use a Docker network shared only with the proxy, or firewall it. (Unraid's template publishes the port on all interfaces of the server, so it's reachable from your LAN; that's usually acceptable at home, but don't forward it on the router.)

The per-username limit (10 failures per 15 minutes) works regardless of the proxy setup.

**Checking it:** the app logs a warning (once per process) when what arrives doesn't match the setting: proxy headers with `TRUSTED_PROXY_COUNT=0`, requests without `X-Forwarded-For` although a proxy is configured (port reachable directly), fewer addresses in the header than configured proxies, or a missing `X-Forwarded-Proto`. After setting things up, open the app once through the proxy and look at the log (`docker logs <container>`): no warnings means the client IPs are right.

**Uploads** arrive in pieces of at most 16 MB per request, so the proxy needs at least `client_max_body_size 20m` (nginx's default of 1 MB is too small; most other proxies have no limit) and a read timeout of a minute or more.

Example for plain nginx:

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name gallery.example.com;
    # ssl_certificate / ssl_certificate_key (e.g. from certbot)

    client_max_body_size 20m;     # uploads arrive in 4 MB pieces (app limit: 16 MB per request)
    proxy_read_timeout   300s;
    proxy_send_timeout   300s;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Publishing the image

`.github/workflows/docker-publish.yml` runs the tests and builds the image for amd64 and arm64:
- every push to `main` → `ghcr.io/n00b42/secure-media-gallery:edge`
- a tag like `v1.2.0` → `:1.2.0`, `:1.2`, `:1` and `:latest` (`git tag v1.2.0 && git push --tags`)

It uses the built-in `GITHUB_TOKEN`; nothing to configure. After the first run, check the package under GitHub → *Packages* and make it public if Unraid should pull it without logging in. Public images and builds of public repositories are free on GitHub.

### Without Docker

```bash
poetry install --only main
poetry run python src/manage.py init-db
poetry run gunicorn --worker-class gthread --workers 2 --threads 4 --timeout 60 \
    --bind 127.0.0.1:5000 src.app:app
```

Use `gthread` workers: gunicorn's default `sync` workers are killed after `--timeout` seconds, which aborts long uploads.

### Testing over plain HTTP
- Local development: `APP_ENV=development`
- Production build (e.g. Docker) on `http://localhost`: `SESSION_COOKIE_SECURE=false` (logs a warning; never on a reachable server)
- From other devices (phone, LAN): use HTTPS, e.g. Caddy with its internal CA or a certificate from `mkcert`. Plain HTTP on a LAN address can't work, because browsers disable WebCrypto there

### Backups
Back up the whole `DATA_DIR`. SQLite runs in WAL mode, so either stop the app first or copy the database with `sqlite3 run/secure_gallery.db ".backup backup.db"` and then copy `uploads/`. Without the database the encrypted uploads can't be decrypted, and vice versa.

## Project structure

```
src/
  app.py          app factory and `app` instance (gunicorn: src.app:app)
  config.py       configuration (environment / .env)
  models.py       SQLAlchemy models
  routes.py       blueprints: auth, gallery, album, api
  security.py     key derivation, rate limiting, validation, CSP and headers
  assets.py       content-hashed static URLs (asset_url)
  extensions.py   db, login_manager
  manage.py       management CLI
  templates/      Jinja templates
  static/         CSS, browser-side encryption (js/e2e-encryption.js), service worker (js/sw.js), fonts, app icons
tests/            pytest suite
run/              DATA_DIR default: database + uploads (not in git)
```

## Database schema

| Table | Columns |
|---|---|
| `user` | `id`, `username` (unique, lowercase), `password_hash` (scrypt hash of the auth key), `public_key` (RSA SPKI, base64), `wrapped_private_key` (encrypted private key), `created_at` |
| `user_session` | `id` (public), `token_hash`, `user_id`, `created_at`, `last_seen_at`, `expires_at`, `user_agent` (one row per signed-in browser) |
| `invite_key` | `id`, `key_hash` (SHA-256 of the invite key), `created_at`, `used_at`, `used_by_user_id` |
| `album` | `id`, `title`, `description`, `owner_id`, `created_at` |
| `album_shares` | `album_id`, `user_id` (who an album is shared with) |
| `media` | `id`, `album_id`, `filename` (random on-disk name in `uploads/`), `file_type` (`image`/`video`), `file_size` (ciphertext), `uploaded_by_id`, `nonce_b64`, `chunk_size`, `encrypted_filename`, `video_thumbnail_data` (encrypted), `created_at` |
| `pending_upload` | unfinished uploads: `token`, `album_id`, `user_id`, `total_size`, `received`, chunk format, encrypted metadata and file keys; data in `uploads/partial/<token>.part` |
| `media_keys` | `id`, `media_id`, `user_id`, `encrypted_key` (file key encrypted for that user), `created_at`; unique per (media, user) |
| `auth_throttle` | `key`, `failures`, `window_start` (rate-limit counters) |

There are no migrations before the first production release: after schema changes, empty `DATA_DIR` and run `init-db` again.

## HTTP endpoints

| Method and path | Purpose |
|---|---|
| `GET/POST /register`, `GET/POST /login`, `POST /logout` | Authentication (POST bodies are JSON with the derived auth key) |
| `GET /`, `GET /dashboard` | Albums you own and albums shared with you |
| `GET /account` | Password change, signed-in devices, fingerprint unlock, key fingerprints |
| `POST /account/sessions/<id>/revoke`, `POST /account/sessions/revoke-others` | Sign out a device / all other devices |
| `POST /api/account/password` | Change the password (derived keys + re-encrypted private key) |
| `GET /album/<id>` | Album page (decryption happens in the browser) |
| `GET /media/<id>/raw` | Encrypted file blob |
| `GET/POST /create`, `GET/POST /<id>/edit` | Create / rename an album (edit: owner only) |
| `GET /<id>/upload` | Upload page |
| `GET/POST /<id>/share`, `POST /<id>/remove-user/<user_id>` | Share / revoke (owner only) |
| `POST /<id>/delete`, `POST /<id>/delete-media/<media_id>` | Delete album / file (owner only) |
| `GET/POST /api/keys/me`, `GET/POST /api/keys/me/private` | Your public key and encrypted private key |
| `GET /api/keys/<user_id>` | Public key of a user you share an album with |
| `GET /api/media/<id>/key` | Your encrypted key for a file |
| `GET /api/album/<id>/owner-keys`, `POST /api/album/<id>/share-keys` | Re-encrypt an album's file keys for a new member (owner only) |
| `POST /api/album/<id>/uploads`, `GET /api/album/<id>/uploads` | Start an upload / list your unfinished uploads (for resuming) |
| `GET/PUT/DELETE /api/uploads/<token>`, `POST /api/uploads/<token>/complete` | Upload status, send one encrypted piece (`?offset=`), discard, finish |
| `GET /manifest.webmanifest`, `GET /sw.js` | Web app manifest and service worker (installable app, streaming decryption under `/__stream/…`) |

## Troubleshooting

- **"Database schema is outdated"**: the schema changed. Empty `DATA_DIR` (e.g. `rm -rf run/`), then run `init-db` and `create-invite`
- **"Encryption is unavailable … HTTPS"**: you opened the app over plain HTTP on an address other than `localhost`; see *Testing over plain HTTP*
- **Login works but you're immediately logged out again** (Docker over HTTP): set `SESSION_COOKIE_SECURE=false` for local testing, or use HTTPS
- **Uploads fail with 413 behind nginx**: set `client_max_body_size 20m` (see above). A 413 from the app itself means the file is above `MAX_FILE_SIZE` or the storage quota is used up
- **A video doesn't play or a download fails in a private window**: some browsers disable service workers there. Small files fall back to in-memory decryption; for files over 512 MB use a normal window
- **An upload was interrupted**: open the upload page again and select the same file; it continues where it stopped. Unfinished uploads are listed there and can be discarded
- **The password is asked again in a new tab**: the unlocked key is cached per browser tab only (in the installed app: each time the app is opened). Enable fingerprint unlock on the *Account* page to use the fingerprint instead
- **Fingerprint sign-in disappeared**: it's stored per browser; clearing site data removes it. After a password change, or if the account was recreated, the saved sign-in no longer matches and is removed automatically. Set it up again on the *Account* page

## Reporting security issues

See [SECURITY.md](SECURITY.md); please report privately, not as a public issue.

## Development

See [DEVELOPMENT.md](DEVELOPMENT.md).

## License

MIT, see [LICENSE](LICENSE). Bundled fonts: SIL Open Font License 1.1 (`src/static/fonts/`).
