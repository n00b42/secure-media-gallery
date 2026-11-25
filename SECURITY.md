# Security Policy

## Reporting a vulnerability

Please **don't open a public issue** for security problems. Report them privately through GitHub:
*Security* tab of this repository → *Report a vulnerability*.

Helpful to include:
- what an attacker can do, and what they need for it (an account? membership of a shared album? access to the server or database?)
- steps to reproduce, or a proof of concept
- the version or commit you tested

This is a hobby project maintained in spare time. Reports are answered on a best-effort basis, usually within a few days; fixes for confirmed issues get priority over everything else. You'll be credited in the release notes unless you prefer otherwise.

## Supported versions

Only the latest release (and the `edge` image built from `main`) receives security fixes.

## Scope and threat model

The design goals and their limits are described in the README, section *Security model*. In short:

**In scope**, for example:
- reading or modifying another user's files, file names, keys or albums without being given access
- bypassing album membership checks or revocation
- recovering plaintext, file keys or private keys from what the server stores
- cross-site scripting, CSRF, or other ways for a website or another user to act on a user's behalf
- bypassing the login rate limits when deployed as documented (see *Behind an HTTPS reverse proxy*)
- weaknesses in the chunked file format (reordering, truncation, mixing files undetected)

**Known limitations** (documented, not vulnerabilities):
- The server delivers the JavaScript that encrypts. An operator or attacker who controls the server can serve modified code; end-to-end encryption protects against database or disk theft and an honest-but-curious operator, not an actively malicious server.
- Files or keys that a user downloaded before their access was revoked can't be recalled.
- Visible to the server: whether a file is an image or a video, its size, uploader and upload time, album titles and descriptions, usernames.
- An attacker who steals the database can try to guess a user's password offline against their encrypted private-key backup. Strong passwords are the defence.
- Per-IP rate limiting depends on a correctly configured reverse proxy (`TRUSTED_PROXY_COUNT`).
- Members of a shared album can upload files, which count against the album owner's `USER_STORAGE_QUOTA` (unlimited by default). They can also upload files that other members can't decrypt.
- There is no password reset: by design, nobody (including the server operator) can recover a forgotten password.
