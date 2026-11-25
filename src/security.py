"""Security helpers: key derivation, rate limiting, input validation, HTTP headers."""

import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import math
import re
import secrets
import unicodedata
from datetime import timedelta

from argon2.low_level import Type, hash_secret_raw
from flask import abort, g, jsonify, request
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

from src.extensions import db

# ---------------------------------------------------------------------------
# Account key derivation — MUST stay identical to src/static/js/e2e-encryption.js
# ---------------------------------------------------------------------------
#
#   master   = Argon2id(NFC(password), salt="secure-media-gallery|v3|" + username,
#                       memory 64 MiB, 3 passes, 1 lane, 32 bytes)
#   auth_key = HKDF-SHA256(master, salt=HKDF_SALT, info="auth")  -> sent to server (hex)
#   wrap_key = HKDF-SHA256(master, salt=HKDF_SALT, info="wrap")  -> never leaves the browser
#
# The server stores only a Werkzeug (scrypt) hash of auth_key. HKDF outputs with
# different info strings are independent, so auth_key reveals nothing about wrap_key.

# Argon2id is memory-hard: every password guess needs 64 MiB of memory, which
# makes guessing on GPUs/ASICs far more expensive than with PBKDF2.
ARGON2_MEMORY_KIB = 64 * 1024
ARGON2_PASSES = 3
ARGON2_LANES = 1
KDF_SALT_PREFIX = 'secure-media-gallery|v3|'
HKDF_SALT = b'secure-media-gallery|hkdf|v2'
MIN_PASSWORD_LENGTH = 8

AUTH_KEY_RE = re.compile(r'^[0-9a-f]{64}$')
USERNAME_RE = re.compile(r'^[a-z0-9._-]+$')


def normalize_username(username):
    return (username or '').strip().lower()


def _hkdf_sha256(ikm, salt, info, length=32):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, block, counter = b'', b'', 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def derive_account_keys(username, password):
    """Python twin of E2EEncryptionManager.deriveAccountKeys (for the CLI and tests)."""
    salt = (KDF_SALT_PREFIX + normalize_username(username)).encode('utf-8')
    pw = unicodedata.normalize('NFC', password).encode('utf-8')
    master = hash_secret_raw(
        pw,
        salt,
        time_cost=ARGON2_PASSES,
        memory_cost=ARGON2_MEMORY_KIB,
        parallelism=ARGON2_LANES,
        hash_len=32,
        type=Type.ID,
    )
    return {
        'auth_key_hex': _hkdf_sha256(master, HKDF_SALT, b'auth').hex(),
        'wrap_key_b64': base64.b64encode(_hkdf_sha256(master, HKDF_SALT, b'wrap')).decode(),
    }


# Used to equalize timing when the username does not exist.
_DUMMY_HASH = generate_password_hash(secrets.token_hex(32))


def burn_password_check(value):
    check_password_hash(_DUMMY_HASH, value or '')


# ---------------------------------------------------------------------------
# Rate limiting (DB-backed so it is shared by all gunicorn workers)
# ---------------------------------------------------------------------------


def client_ip_bucket():
    """Client IP for rate limiting. IPv6 is grouped by /64 (one subscriber)."""
    raw = request.remote_addr or 'unknown'
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return raw[:64]
    if ip.version == 6:
        if ip.ipv4_mapped:
            return str(ip.ipv4_mapped)
        return str(ipaddress.ip_network(f'{ip}/64', strict=False))
    return str(ip)


def username_throttle_key(prefix, username):
    digest = hashlib.sha256(normalize_username(username).encode('utf-8')).hexdigest()[:40]
    return f'{prefix}:{digest}'


def _utcnow():
    from src.models import utcnow

    return utcnow()


def throttle_retry_after(rules):
    """rules: iterable of (key, max_failures, window_seconds). Returns seconds to wait (0 = ok)."""
    from src.models import AuthThrottle

    now = _utcnow()
    worst = 0
    for key, max_failures, window in rules:
        row = db.session.get(AuthThrottle, key)
        if row is None:
            continue
        window_end = row.window_start + timedelta(seconds=window)
        if window_end > now and row.failures >= max_failures:
            worst = max(worst, math.ceil((window_end - now).total_seconds()))
    return worst


def throttle_record_failure(rules):
    from src.models import AuthThrottle

    for _attempt in range(3):
        now = _utcnow()
        for key, _max_failures, window in rules:
            row = db.session.get(AuthThrottle, key)
            if row is None:
                db.session.add(AuthThrottle(key=key, failures=1, window_start=now))
            elif row.window_start + timedelta(seconds=window) <= now:
                row.failures = 1
                row.window_start = now
            else:
                row.failures = AuthThrottle.failures + 1  # atomic increment in SQL
        # Opportunistic cleanup of long-expired counters.
        AuthThrottle.query.filter(AuthThrottle.window_start < now - timedelta(days=1)).delete(
            synchronize_session=False
        )
        try:
            db.session.commit()
            return
        except IntegrityError:  # another worker inserted the same key concurrently
            db.session.rollback()


def throttle_clear(key):
    from src.models import AuthThrottle

    AuthThrottle.query.filter_by(key=key).delete(synchronize_session=False)
    db.session.commit()


def too_many_requests(retry_after):
    response = jsonify(
        {
            'error': 'Too many failed attempts. Please wait and try again.',
            'retry_after': retry_after,
        }
    )
    response.status_code = 429
    response.headers['Retry-After'] = str(retry_after)
    return response


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def json_error(message, status=400):
    response = jsonify({'error': message})
    response.status_code = status
    return response


def json_object():
    """Return the request's JSON body as a dict, or abort with 400.

    Requires Content-Type: application/json (no force=True). Browsers cannot send
    that cross-origin without a CORS preflight, which this app never grants.
    """
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        abort(400, description='Expected a JSON object with Content-Type: application/json')
    return data


def get_str(data, name, max_length, required=True, strip=True):
    value = data.get(name)
    if value is None or value == '':
        if required:
            abort(400, description=f'{name} is required')
        return ''
    if not isinstance(value, str):
        abort(400, description=f'{name} must be a string')
    if strip:
        value = value.strip()
    if required and not value:
        abort(400, description=f'{name} is required')
    if len(value) > max_length:
        abort(400, description=f'{name} is too long (max {max_length} characters)')
    return value


def get_int(data, name):
    value = data.get(name)
    # bool is a subclass of int; reject it explicitly.
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        abort(400, description=f'{name} must be a positive integer')
    return value


def is_valid_username(username, min_length, max_length):
    return min_length <= len(username) <= max_length and bool(USERNAME_RE.match(username))


def is_valid_auth_key(auth_key):
    return isinstance(auth_key, str) and bool(AUTH_KEY_RE.match(auth_key))


def decode_b64(value, max_length):
    """Strictly decode standard base64; returns bytes or None."""
    if not isinstance(value, str) or not value or len(value) > max_length:
        return None
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None


def is_valid_public_key(value, max_length, min_bits):
    der = decode_b64(value, max_length)
    if der is None:
        return False
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    try:
        key = load_der_public_key(der)
    except (ValueError, TypeError):
        return False
    return isinstance(key, rsa.RSAPublicKey) and key.key_size >= min_bits


def is_valid_wrapped_private_key(value, max_length):
    """Accept only the current (v2) wrapping format: {"v": 2, "iv": b64(12), "data": b64}."""
    if not isinstance(value, str) or not value or len(value) > max_length:
        return False
    try:
        payload = json.loads(value)
    except ValueError:
        return False
    if not isinstance(payload, dict) or payload.get('v') != 2:
        return False
    iv = decode_b64(payload.get('iv'), 64)
    data = decode_b64(payload.get('data'), max_length)
    return iv is not None and len(iv) == 12 and bool(data)


def is_valid_encrypted_key(value, max_length):
    raw = decode_b64(value, max_length)
    return raw is not None and len(raw) >= 128


def is_valid_encrypted_string(value, max_length):
    """Format produced by encryptStringWithRawKey: {"version": 1, "iv_b64", "data_b64"}."""
    if not isinstance(value, str) or not value or len(value) > max_length:
        return False
    try:
        payload = json.loads(value)
    except ValueError:
        return False
    if not isinstance(payload, dict) or payload.get('version') != 1:
        return False
    iv = decode_b64(payload.get('iv_b64'), 64)
    data = decode_b64(payload.get('data_b64'), max_length)
    return iv is not None and len(iv) == 12 and data is not None and len(data) >= 16  # GCM tag


# ---------------------------------------------------------------------------
# HTTP hardening: proxy handling, CSP with nonces, security headers, JSON errors
# ---------------------------------------------------------------------------


def build_csp(nonce):
    return '; '.join(
        [
            "default-src 'self'",
            # 'wasm-unsafe-eval' only allows compiling WebAssembly (Argon2), not JS eval().
            f"script-src 'self' 'nonce-{nonce}' 'wasm-unsafe-eval'",
            "style-src 'self'",
            "img-src 'self' data: blob:",
            "media-src 'self' blob:",
            "font-src 'self'",
            "connect-src 'self'",
            "object-src 'none'",
            "base-uri 'none'",
            "form-action 'self'",
            "frame-ancestors 'none'",
        ]
    )


def init_security(app):
    proxies = app.config.get('TRUSTED_PROXY_COUNT', 0)
    if proxies > 0:
        app.wsgi_app = ProxyFix(
            app.wsgi_app, x_for=proxies, x_proto=proxies, x_host=proxies, x_port=proxies
        )

    warned = set()

    def warn_once(kind, message):
        if kind not in warned:
            warned.add(kind)
            app.logger.warning(message)

    @app.before_request
    def _check_proxy_setup():
        """Log (once per process) when the proxy headers don't match TRUSTED_PROXY_COUNT.

        The per-IP login/registration rate limits are only as good as the client
        IP, which behind a reverse proxy comes from X-Forwarded-For.
        """
        original = request.environ.get('werkzeug.proxy_fix.orig', {}).get('REMOTE_ADDR')
        peer = original or request.remote_addr or ''
        forwarded = request.headers.get('X-Forwarded-For')
        if proxies == 0 and forwarded:
            warn_once(
                'proxy-not-trusted',
                'Requests arrive through a reverse proxy (X-Forwarded-For is set) but '
                "TRUSTED_PROXY_COUNT=0: every client appears with the proxy's IP, so the per-IP "
                'rate limits are shared by all users. Set TRUSTED_PROXY_COUNT to the number of '
                'proxies in front of the app.',
            )
        elif proxies > 0 and not forwarded:
            if peer in ('127.0.0.1', '::1'):
                return  # health check from inside the container
            warn_once(
                'proxy-bypassed',
                f'TRUSTED_PROXY_COUNT={proxies} but a request from {peer} had no X-Forwarded-For '
                'header: the app is reachable without going through the proxy, or the proxy does '
                'not send the header. Clients that reach the app directly can fake their IP and '
                'evade the per-IP rate limits. Make the app port reachable only by the proxy.',
            )
        elif proxies > 0 and len(forwarded.split(',')) < proxies:
            warn_once(
                'proxy-count-too-high',
                f'TRUSTED_PROXY_COUNT={proxies} but X-Forwarded-For lists only '
                f'{len(forwarded.split(","))} address(es): the count is higher than the number of '
                'proxies, so client-supplied addresses would be trusted. Lower TRUSTED_PROXY_COUNT.',
            )
        if proxies > 0 and forwarded and not request.headers.get('X-Forwarded-Proto'):
            warn_once(
                'proxy-no-proto',
                'The reverse proxy does not send X-Forwarded-Proto: HTTPS is not detected '
                '(no HSTS header). Configure the proxy to send X-Forwarded-Proto.',
            )

    @app.before_request
    def _generate_csp_nonce():
        g.csp_nonce = secrets.token_urlsafe(18)

    @app.context_processor
    def _inject_csp_nonce():
        return {'csp_nonce': getattr(g, 'csp_nonce', '')}

    @app.after_request
    def _set_security_headers(response):
        nonce = getattr(g, 'csp_nonce', None) or secrets.token_urlsafe(18)
        response.headers['Content-Security-Policy'] = build_csp(nonce)
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'same-origin'
        response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
        response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
        response.headers['Permissions-Policy'] = (
            'camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()'
        )
        if request.is_secure:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000'
        return response

    @app.errorhandler(HTTPException)
    def _json_errors_for_api(error):
        wants_json = (
            request.path.startswith('/api/')
            or request.is_json
            or (request.method == 'POST' and request.accept_mimetypes.best == 'application/json')
        )
        if not wants_json:
            return error
        response = jsonify({'error': error.description or error.name})
        response.status_code = error.code or 500
        return response
