import base64
import functools
import json
import os
import shutil
import sys
import tempfile

import pytest

# Configure BEFORE the app is imported (config is read at import time).
os.environ['APP_ENV'] = 'testing'
DATA_DIR = tempfile.mkdtemp(prefix='smg-test-data-')
os.environ['DATA_DIR'] = DATA_DIR
UPLOAD_DIR = os.path.join(DATA_DIR, 'uploads')
os.makedirs(UPLOAD_DIR)

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from flask import g  # noqa: E402
from flask.testing import FlaskClient  # noqa: E402

from src.app import app as flask_app  # noqa: E402
from src.extensions import db  # noqa: E402
from src.models import Album, InviteKey, Media, MediaKey, User, hash_invite_key  # noqa: E402
from src.security import derive_account_keys  # noqa: E402


@functools.cache
def auth_key_for(username, password):
    return derive_account_keys(username, password)['auth_key_hex']


@functools.lru_cache(maxsize=1)
def public_key_b64():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    der = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(der).decode()


def wrapped_key_v2():
    return json.dumps(
        {
            'v': 2,
            'iv': base64.b64encode(b'\x01' * 12).decode(),
            'data': base64.b64encode(b'\x02' * 64).decode(),
        }
    )


FAKE_ENCRYPTED_KEY = base64.b64encode(b'\x03' * 512).decode()
FAKE_NONCE = base64.b64encode(b'\x04' * 8).decode()
CHUNK = 64 * 1024  # smallest chunk size the server accepts; keeps tests fast


def fake_encrypted_string(payload=b'\x05' * 32):
    """Same shape as encryptStringWithRawKey output (content is opaque to the server)."""
    return json.dumps(
        {
            'version': 1,
            'iv_b64': base64.b64encode(b'\x06' * 12).decode(),
            'data_b64': base64.b64encode(payload).decode(),
        }
    )


class IsolatedClient(FlaskClient):
    """Tests keep one app context open (so they can query models directly), and
    Flask then reuses it for every test request. Reset per-request state so each
    request behaves like a fresh one in production (own `g`, fresh ORM state)."""

    def open(self, *args, **kwargs):
        g.pop('_login_user', None)
        db.session.expire_all()
        try:
            return super().open(*args, **kwargs)
        finally:
            g.pop('_login_user', None)


flask_app.test_client_class = IsolatedClient


@pytest.fixture
def app():
    with flask_app.app_context():
        db.drop_all()
        db.create_all()
        yield flask_app
        db.session.remove()
        db.drop_all()
    for name in os.listdir(UPLOAD_DIR):
        path = os.path.join(UPLOAD_DIR, name)
        if os.path.isdir(path):
            shutil.rmtree(path)
        else:
            os.remove(path)


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def make_client(app):
    return app.test_client


@pytest.fixture
def make_user(app):
    def _make(username, password='correct horse', with_keys=True):
        user = User(username=username)
        user.set_auth_key(auth_key_for(username, password))
        if with_keys:
            user.public_key = public_key_b64()
            user.wrapped_private_key = wrapped_key_v2()
        db.session.add(user)
        db.session.commit()
        return user

    return _make


@pytest.fixture
def login(app):
    def _login(client, username, password='correct horse', **extra):
        return client.post(
            '/login',
            json={
                'username': username,
                'auth_key': auth_key_for(username, password),
                **extra,
            },
        )

    return _login


@pytest.fixture
def make_album(app):
    def _make(owner, title='Album', shared_with=()):
        album = Album(title=title, owner_id=owner.id)
        album.shared_users.extend(shared_with)
        db.session.add(album)
        db.session.commit()
        return album

    return _make


@pytest.fixture
def make_media(app):
    def _make(album, key_users=()):
        name = f'e2e_test_{album.id}_{Media.query.count()}'
        path = os.path.join(UPLOAD_DIR, name)
        with open(path, 'wb') as f:
            f.write(b'ciphertext')
        media = Media(
            album_id=album.id,
            filename=name,
            encrypted_filename=fake_encrypted_string(),
            file_type='image',
            nonce_b64=FAKE_NONCE,
            chunk_size=CHUNK,
            uploaded_by_id=album.owner_id,
            file_size=10,
        )
        db.session.add(media)
        db.session.flush()
        for user in key_users:
            db.session.add(
                MediaKey(media_id=media.id, user_id=user.id, encrypted_key=f'KEY-{user.username}')
            )
        db.session.commit()
        return media

    return _make


@pytest.fixture
def make_invite(app):
    def _make(raw='inv_test_key'):
        db.session.add(InviteKey(key_hash=hash_invite_key(raw)))
        db.session.commit()
        return raw

    return _make
