# Config for Secure Media Gallery
import os
import warnings
from datetime import timedelta

from dotenv import load_dotenv

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Load .env BEFORE the Config classes below read os.environ. (Previously this
# happened after import, so values from .env — including SECRET_KEY — were
# silently ignored unless they were also exported in the shell.)
load_dotenv()


def env_bool(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {'1', 'true', 'yes', 'on'}


def parse_size(value):
    """'500M', '20G', '1.5T' or plain bytes -> int bytes. 0 means unlimited where allowed."""
    text = str(value).strip().upper().removesuffix('B')
    units = {'K': 1024, 'M': 1024**2, 'G': 1024**3, 'T': 1024**4}
    if text and text[-1] in units:
        return int(float(text[:-1]) * units[text[-1]])
    return int(text)


def env_size(name, default):
    value = os.getenv(name)
    if value is None or not value.strip():
        return parse_size(default)
    return parse_size(value)


def env_int(name, default):
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    return int(value)


# Placeholder values that have ever shipped in this repo's examples/defaults.
KNOWN_INSECURE_SECRET_KEYS = frozenset(
    {
        'dev-key-change-in-production',
        'change-this-in-production',
        'your-secret-key-here-change-in-production',
    }
)
MIN_SECRET_KEY_LENGTH = 32


class InsecureConfigurationError(RuntimeError):
    pass


def validate_secret_key(secret_key):
    """Raise if SECRET_KEY is missing, a known placeholder, or too short.

    Flask signs the session cookie with SECRET_KEY; anyone who knows it can
    forge a session and log in as any user.
    """
    hint = 'Generate one with: python -c "import secrets; print(secrets.token_hex(32))"'
    if not secret_key:
        raise InsecureConfigurationError(f'SECRET_KEY is not set. {hint}')
    if secret_key in KNOWN_INSECURE_SECRET_KEYS:
        raise InsecureConfigurationError(f'SECRET_KEY is a published placeholder value. {hint}')
    if len(secret_key) < MIN_SECRET_KEY_LENGTH:
        raise InsecureConfigurationError(
            f'SECRET_KEY must be at least {MIN_SECRET_KEY_LENGTH} characters. {hint}'
        )


def resolve_data_dir():
    """DATA_DIR holds everything the app writes: the SQLite database and uploads.

    Relative paths are resolved against the project root (not the current
    directory), so DATA_DIR=run always means <project>/run. Docker uses /data.
    The default 'run' is excluded from git.
    """
    return os.path.normpath(os.path.join(PROJECT_ROOT, os.getenv('DATA_DIR') or 'run'))


DATABASE_FILENAME = 'secure_gallery.db'


class Config:
    """Base configuration"""

    SECRET_KEY = os.getenv('SECRET_KEY')
    DATA_DIR = resolve_data_dir()
    UPLOAD_FOLDER = os.path.join(DATA_DIR, 'uploads')
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(DATA_DIR, DATABASE_FILENAME)
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # Wait up to 15 s for a lock instead of failing with "database is locked"
    # when several gunicorn workers write at once (WAL mode is enabled in app.py).
    SQLALCHEMY_ENGINE_OPTIONS = {'connect_args': {'timeout': 15}}
    # Files are uploaded in encrypted chunks, so a single HTTP request stays small
    # no matter how big the file is (largest request: one 4 MiB chunk, or the
    # metadata with an encrypted video thumbnail).
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    # Size limits for files (0 = unlimited). Accepts 500M, 20G, 1T or bytes.
    MAX_FILE_SIZE = env_size('MAX_FILE_SIZE', '0')
    # Per user: everything in the albums they own (also other members' uploads), incl. unfinished.
    USER_STORAGE_QUOTA = env_size('USER_STORAGE_QUOTA', '0')
    MIN_FREE_DISK_SPACE = env_size(
        'MIN_FREE_DISK_SPACE', '1G'
    )  # refuse uploads that would go below
    # Unfinished uploads are resumable for this long, then deleted.
    UPLOAD_EXPIRY_HOURS = env_int('UPLOAD_EXPIRY_HOURS', 7 * 24)
    ALBUM_OVERVIEW_THUMBNAILS_ENABLED = env_bool('ALBUM_OVERVIEW_THUMBNAILS_ENABLED', True)

    # Session configuration: logins expire 24 h after login (sessions are marked
    # permanent at login, otherwise this lifetime would not apply).
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    # Sessions also end after this long without any request (uploads, video
    # streaming and page loads all count as activity).
    SESSION_IDLE_TIMEOUT = timedelta(minutes=env_int('SESSION_IDLE_TIMEOUT_MINUTES', 120))
    SESSION_REFRESH_EACH_REQUEST = False
    # Cookies only over HTTPS. Set SESSION_COOKIE_SECURE=false to test the
    # production build over plain HTTP — note that browsers only expose the
    # WebCrypto API on HTTPS or http://localhost / 127.0.0.1 anyway.
    SESSION_COOKIE_SECURE = env_bool('SESSION_COOKIE_SECURE', True)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

    # CSRF tokens are valid for the whole login session (pages stay open for long
    # uploads). The token check alone is sufficient; the additional Referer check
    # Flask-WTF does on HTTPS is off because it breaks behind proxies that don't
    # forward the Host header.
    WTF_CSRF_TIME_LIMIT = None
    WTF_CSRF_SSL_STRICT = False

    # Number of reverse proxies in front of the app that set X-Forwarded-* headers.
    # 0 = app is reached directly (headers are ignored, they could be spoofed).
    # Must be correct for rate limiting (client IP) and HTTPS detection.
    TRUSTED_PROXY_COUNT = env_int('TRUSTED_PROXY_COUNT', 0)

    # Rate limiting for authentication (fixed windows, failures only)
    LOGIN_IP_MAX_FAILURES = env_int('LOGIN_IP_MAX_FAILURES', 20)
    LOGIN_IP_WINDOW_SECONDS = env_int('LOGIN_IP_WINDOW_SECONDS', 15 * 60)
    LOGIN_USER_MAX_FAILURES = env_int('LOGIN_USER_MAX_FAILURES', 10)
    LOGIN_USER_WINDOW_SECONDS = env_int('LOGIN_USER_WINDOW_SECONDS', 15 * 60)
    REGISTER_IP_MAX_FAILURES = env_int('REGISTER_IP_MAX_FAILURES', 10)
    REGISTER_IP_WINDOW_SECONDS = env_int('REGISTER_IP_WINDOW_SECONDS', 60 * 60)
    # Share form: usernames that don't exist (or can't receive shares) per user.
    SHARE_LOOKUP_MAX_FAILURES = env_int('SHARE_LOOKUP_MAX_FAILURES', 20)
    SHARE_LOOKUP_WINDOW_SECONDS = env_int('SHARE_LOOKUP_WINDOW_SECONDS', 60 * 60)

    # Input size limits
    MIN_USERNAME_LENGTH = 3
    MAX_USERNAME_LENGTH = 80
    MAX_INVITE_KEY_LENGTH = 128
    MAX_ALBUM_TITLE_LENGTH = 200
    MAX_ALBUM_DESCRIPTION_LENGTH = 5000
    MAX_PUBLIC_KEY_LENGTH = 2048  # RSA-4096 SPKI base64 is ~736 chars
    MAX_WRAPPED_PRIVATE_KEY_LENGTH = 8192  # wrapped RSA-4096 PKCS#8 JSON is ~3.3 KB
    MAX_ENCRYPTED_KEY_LENGTH = 1024  # RSA-4096 OAEP ciphertext base64 is 684 chars
    MAX_VIDEO_THUMBNAIL_LENGTH = 1024 * 1024
    MAX_ENCRYPTED_FILENAME_LENGTH = 4096  # encrypted 255-char name is well under 2 KB
    MAX_SHARE_KEYS_PER_REQUEST = 10000
    MIN_RSA_KEY_BITS = 2048

    # Chunked file format: plaintext chunk size range accepted from clients
    # (the browser uses 4 MiB). Each encrypted chunk is 16 bytes longer (GCM tag).
    MIN_CHUNK_SIZE = 64 * 1024
    MAX_CHUNK_SIZE = 8 * 1024 * 1024


class DevelopmentConfig(Config):
    """Development configuration"""

    DEBUG = True
    TESTING = False
    SESSION_COOKIE_SECURE = False
    SECRET_KEY = os.getenv('SECRET_KEY') or 'dev-key-change-in-production'


class ProductionConfig(Config):
    """Production configuration"""

    DEBUG = False
    TESTING = False
    REQUIRE_STRONG_SECRET_KEY = True


class TestingConfig(Config):
    """Testing configuration"""

    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False
    SECRET_KEY = 'testing-secret-key-not-for-production-use'


def get_config():
    """Select the config class from APP_ENV: production (default) | development | testing."""
    if os.getenv('FLASK_ENV') and not os.getenv('APP_ENV'):
        # Flask itself dropped FLASK_ENV in 2.3 and this app no longer reads it.
        warnings.warn(
            'FLASK_ENV is ignored; use APP_ENV instead (running as production).', stacklevel=2
        )
    env = os.getenv('APP_ENV', 'production')

    if env == 'development':
        return DevelopmentConfig
    elif env == 'testing':
        return TestingConfig
    else:
        return ProductionConfig
