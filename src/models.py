import hashlib
import secrets
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from src.extensions import db

if TYPE_CHECKING:
    # db.Model is created at runtime, so type checkers can't see it.
    from flask_sqlalchemy.model import Model
else:
    Model = db.Model


def utcnow():
    """Current UTC time as a naive datetime (SQLite DateTime columns are naive).

    Replaces the deprecated datetime.utcnow() with identical values.
    """
    return datetime.now(UTC).replace(tzinfo=None)


class User(UserMixin, Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    # Werkzeug (scrypt) hash of the auth key the browser derives from the
    # password. The password itself is never sent to the server.
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow)

    # E2E: the user's RSA public key (SPKI, base64), uploaded at registration.
    public_key = db.Column(db.Text, nullable=True)

    # The private key, AES-GCM wrapped in the browser with the password-derived
    # wrap key (JSON {v, iv, data}). The server only ever holds this ciphertext.
    wrapped_private_key = db.Column(db.Text, nullable=True)

    albums = db.relationship('Album', backref='owner', lazy=True, foreign_keys='Album.owner_id')
    accessed_albums = db.relationship(
        'Album',
        secondary='album_shares',
        back_populates='shared_users',
    )

    def set_auth_key(self, auth_key):
        """Store a hash of the client-derived auth key (never the password)."""
        self.password_hash = generate_password_hash(auth_key)

    def check_auth_key(self, auth_key):
        return check_password_hash(self.password_hash, auth_key)

    def has_e2e_key(self):
        return self.public_key is not None


def generate_invite_key():
    return f'inv_{secrets.token_urlsafe(18)}'


def normalize_invite_key(invite_key):
    return (invite_key or '').strip()


def hash_invite_key(invite_key):
    normalized = normalize_invite_key(invite_key)
    return hashlib.sha256(normalized.encode('utf-8')).hexdigest()


class UserSession(Model):
    """A signed-in browser. The session cookie carries a random token; only its
    SHA-256 is stored here, so a copy of the database holds no usable sessions.
    Deleting the row signs that browser out immediately."""

    __tablename__ = 'user_session'

    id = db.Column(db.String(24), primary_key=True)  # public id: shown in the list, used to revoke
    token_hash = db.Column(db.String(64), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    last_seen_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    user_agent = db.Column(db.String(200), nullable=True)


class InviteKey(Model):
    id = db.Column(db.Integer, primary_key=True)
    key_hash = db.Column(db.String(64), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    used_at = db.Column(db.DateTime, nullable=True)
    used_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    used_by_user = db.relationship('User', backref='used_invite_keys', lazy=True)

    def __repr__(self):
        return f'<InviteKey id={self.id} used={self.used_at is not None}>'


class Album(Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow)

    media = db.relationship('Media', backref='album', lazy=True, cascade='all, delete-orphan')
    shared_users = db.relationship(
        'User',
        secondary='album_shares',
        back_populates='accessed_albums',
    )

    def __repr__(self):
        return f'<Album {self.title}>'


album_shares = db.Table(
    'album_shares',
    db.Column('album_id', db.Integer, db.ForeignKey('album.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
)


class Media(Model):
    id = db.Column(db.Integer, primary_key=True)
    album_id = db.Column(db.Integer, db.ForeignKey('album.id'), nullable=False)
    # Random on-disk name (e2e_<uuid>) inside UPLOAD_FOLDER. Only the name is
    # stored, never a full path, so the data folder can be moved freely.
    filename = db.Column(db.String(255), nullable=False, unique=True)

    # Visible to the server (needed to render the grid before decryption):
    file_type = db.Column(db.String(20), nullable=False)  # 'image' or 'video'
    file_size = db.Column(db.BigInteger, nullable=False)  # size of the ciphertext
    created_at = db.Column(db.DateTime, default=utcnow)
    # Counted against this user's storage quota (may differ from the album owner).
    uploaded_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True, index=True)

    # Chunked encryption format (not secret): the plaintext is split into
    # chunk_size pieces, each AES-GCM encrypted with the file key under
    # IV = nonce (8 bytes) || chunk index (4 bytes, big endian) and
    # additional data = chunk index || final-chunk flag. Every encrypted chunk
    # is chunk_size + 16 bytes except the last one.
    nonce_b64 = db.Column(db.String(16), nullable=False)
    chunk_size = db.Column(db.Integer, nullable=False)

    # The original file name, encrypted in the browser with the file's AES key:
    # JSON {"version": 1, "iv_b64": ..., "data_b64": ...}. The server never sees it.
    encrypted_filename = db.Column(db.Text, nullable=False)

    # Upload-time preview thumbnail for videos, encrypted client-side with the file key
    video_thumbnail_data = db.Column(db.Text, nullable=True)

    # Relationship to per-user encrypted file keys
    media_keys = db.relationship(
        'MediaKey', backref='media', lazy=True, cascade='all, delete-orphan'
    )

    def __repr__(self):
        return f'<Media {self.id} album={self.album_id}>'


class PendingUpload(Model):
    """A file upload in progress (resumable). Becomes a Media row when complete.

    The encrypted chunks are appended to <UPLOAD_FOLDER>/partial/<token>.part.
    """

    __tablename__ = 'pending_upload'

    token = db.Column(db.String(64), primary_key=True)
    album_id = db.Column(db.Integer, db.ForeignKey('album.id'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    file_type = db.Column(db.String(20), nullable=False)
    total_size = db.Column(db.BigInteger, nullable=False)  # ciphertext bytes expected
    received = db.Column(db.BigInteger, nullable=False, default=0)
    nonce_b64 = db.Column(db.String(16), nullable=False)
    chunk_size = db.Column(db.Integer, nullable=False)
    encrypted_filename = db.Column(db.Text, nullable=False)
    video_thumbnail_data = db.Column(db.Text, nullable=True)
    # Encrypted (with the file key) fingerprint of the source file, so the browser
    # can tell whether a re-selected file is the same one before resuming.
    encrypted_check = db.Column(db.Text, nullable=True)
    keys_json = db.Column(db.Text, nullable=False)  # {user_id: encrypted file key}
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=utcnow, nullable=False)


class MediaKey(Model):
    """
    Stores the file's AES key, encrypted with a specific user's RSA public key.

    One row per (media, user) pair.  The server holds the ciphertext but can
    never recover the plaintext AES key because it never has the private key.

    owner_encrypted_key  → file AES key encrypted with the album owner's public key
    shared_encrypted_key → same AES key encrypted with a recipient's public key
    Both are base64-encoded RSA-OAEP ciphertexts.
    """

    __tablename__ = 'media_keys'

    id = db.Column(db.Integer, primary_key=True)
    media_id = db.Column(db.Integer, db.ForeignKey('media.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # RSA-OAEP(user_public_key, raw_aes_key) — base64
    encrypted_key = db.Column(db.Text, nullable=False)

    created_at = db.Column(db.DateTime, default=utcnow)

    # Composite unique constraint: one key entry per (media, user)
    __table_args__ = (db.UniqueConstraint('media_id', 'user_id', name='uq_media_user_key'),)

    def __repr__(self):
        return f'<MediaKey media={self.media_id} user={self.user_id}>'


class AuthThrottle(Model):
    """Failure counter for rate limiting, shared by all worker processes.

    key is e.g. "login-ip:<ip>" or "login-user:<sha256(username)>".
    """

    __tablename__ = 'auth_throttle'

    key = db.Column(db.String(128), primary_key=True)
    failures = db.Column(db.Integer, nullable=False, default=0)
    window_start = db.Column(db.DateTime, nullable=False, index=True)
