import json
import os
import re
import shutil
import subprocess
import sys
from datetime import UTC

import pytest
from conftest import (
    FAKE_ENCRYPTED_KEY,
    PROJECT_ROOT,
    UPLOAD_DIR,
    auth_key_for,
    public_key_b64,
    wrapped_key_v2,
)

from src.config import InsecureConfigurationError, validate_secret_key
from src.extensions import db
from src.models import InviteKey, Media, MediaKey, User
from src.security import derive_account_keys

# ---------------------------------------------------------------------------
# 1. Cross-album key overwrite
# ---------------------------------------------------------------------------


def test_bulk_share_keys_rejects_media_from_other_album(
    client, make_user, make_album, make_media, login
):
    alice, mallory = make_user('alice'), make_user('mallory')
    victim_album = make_album(alice)
    victim_media = make_media(victim_album, key_users=[alice])
    mallory_album = make_album(mallory)

    login(client, 'mallory')
    res = client.post(
        f'/api/album/{mallory_album.id}/share-keys',
        json={
            'user_id': alice.id,
            'keys': [{'media_id': victim_media.id, 'encrypted_key': FAKE_ENCRYPTED_KEY}],
        },
    )
    # alice isn't a member of mallory's album; and the media isn't in it either
    assert res.status_code == 400
    assert (
        MediaKey.query.filter_by(media_id=victim_media.id, user_id=alice.id).one().encrypted_key
        == 'KEY-alice'
    )


def test_bulk_share_keys_rejects_foreign_media_even_for_member(
    client, make_user, make_album, make_media, login
):
    alice, bob = make_user('alice'), make_user('bob')
    victim_album = make_album(alice, shared_with=[bob])
    victim_media = make_media(victim_album, key_users=[alice, bob])
    bob_album = make_album(bob, shared_with=[alice])
    own_media = make_media(bob_album, key_users=[bob])

    login(client, 'bob')
    res = client.post(
        f'/api/album/{bob_album.id}/share-keys',
        json={
            'user_id': alice.id,
            'keys': [
                {'media_id': own_media.id, 'encrypted_key': FAKE_ENCRYPTED_KEY},
                {'media_id': victim_media.id, 'encrypted_key': FAKE_ENCRYPTED_KEY},
            ],
        },
    )
    assert res.status_code == 400
    assert 'not in this album' in res.json['error']
    # all-or-nothing: not even the legitimate entry was written
    assert MediaKey.query.filter_by(media_id=own_media.id, user_id=alice.id).first() is None
    assert (
        MediaKey.query.filter_by(media_id=victim_media.id, user_id=alice.id).one().encrypted_key
        == 'KEY-alice'
    )


def test_bulk_share_keys_happy_path(client, make_user, make_album, make_media, login):
    alice, bob = make_user('alice'), make_user('bob')
    album = make_album(alice, shared_with=[bob])
    media = make_media(album, key_users=[alice])

    login(client, 'alice')
    res = client.post(
        f'/api/album/{album.id}/share-keys',
        json={
            'user_id': bob.id,
            'keys': [{'media_id': media.id, 'encrypted_key': FAKE_ENCRYPTED_KEY}],
        },
    )
    assert res.status_code == 200 and res.json['count'] == 1
    assert (
        MediaKey.query.filter_by(media_id=media.id, user_id=bob.id).one().encrypted_key
        == FAKE_ENCRYPTED_KEY
    )


def test_removed_endpoints_are_gone(client, make_user, make_album, make_media, login):
    alice = make_user('alice')
    media = make_media(make_album(alice), key_users=[alice])
    login(client, 'alice')
    assert client.get('/api/keys/by-username/alice').status_code == 404
    res = client.post(
        f'/api/media/{media.id}/share-key',
        json={'user_id': alice.id, 'encrypted_key': FAKE_ENCRYPTED_KEY},
    )
    assert res.status_code == 404


# ---------------------------------------------------------------------------
# 2. Client-derived auth key: password never sent
# ---------------------------------------------------------------------------


def test_login_with_auth_key(client, make_user, login):
    make_user('alice', 'correct horse')
    res = login(client, 'alice', 'correct horse')
    assert res.status_code == 200 and res.json['status'] == 'ok'
    assert client.get('/dashboard').status_code == 200


def test_login_is_case_insensitive_for_username(client, make_user):
    make_user('alice', 'correct horse')
    res = client.post(
        '/login', json={'username': '  Alice ', 'auth_key': auth_key_for('alice', 'correct horse')}
    )
    assert res.status_code == 200


def test_stored_hash_is_not_a_password_hash(app, make_user):
    from werkzeug.security import check_password_hash

    user = make_user('alice', 'correct horse')
    assert not check_password_hash(user.password_hash, 'correct horse')


def test_login_rejects_malformed_auth_key(client, make_user):
    make_user('alice')
    res = client.post('/login', json={'username': 'alice', 'auth_key': 'correct horse'})
    assert res.status_code == 400


def test_python_and_js_derivation_match():
    node = shutil.which('node')
    if not node:
        pytest.skip('node not installed')
    script = r"""
    const fs = require('fs');
    // The page loads the Argon2 library first; it registers globalThis.hashwasm.
    // exports/module/define are hidden so the UMD bundle takes the browser path.
    new Function('exports', 'module', 'define', fs.readFileSync(process.argv[4], 'utf8'))();
    const src = fs.readFileSync(process.argv[1], 'utf8') + '\nmodule.exports = { e2e };';
    const m = { exports: {} };
    new Function('module', 'require', src)(m, require);
    m.exports.e2e.deriveAccountKeys(process.argv[2], process.argv[3])
      .then(r => console.log(JSON.stringify(r)));
    """
    js_path = os.path.join(PROJECT_ROOT, 'src', 'static', 'js', 'e2e-encryption.js')
    argon2_js = os.path.join(
        PROJECT_ROOT, 'src', 'static', 'vendor', 'hash-wasm', 'argon2.umd.min.js'
    )
    for username, password in [('alice', 'correct horse'), (' Bob.Smith ', 'pässwörd́ü')]:
        out = subprocess.run(
            [node, '-e', script, js_path, username, password, argon2_js],
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        )
        js = json.loads(out.stdout)
        py = derive_account_keys(username, password)
        assert js == {'authKeyHex': py['auth_key_hex'], 'wrapKeyB64': py['wrap_key_b64']}


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def register_payload(username='newuser', invite='inv_test_key', password='long enough'):
    return {
        'username': username,
        'invite_key': invite,
        'auth_key': auth_key_for(username, password),
        'public_key': public_key_b64(),
        'wrapped_private_key': wrapped_key_v2(),
    }


def test_register_success_consumes_invite_and_logs_in(client, make_invite):
    make_invite()
    res = client.post('/register', json=register_payload())
    assert res.status_code == 200 and res.json['status'] == 'ok'
    assert (
        InviteKey.query.one().used_by_user_id == User.query.filter_by(username='newuser').one().id
    )
    assert client.get('/dashboard').status_code == 200
    # invite cannot be reused
    other = client.application.test_client()
    assert other.post('/register', json=register_payload('another')).status_code == 400


def test_register_does_not_reveal_usernames_without_valid_invite(client, make_user, make_invite):
    make_user('alice')
    res = client.post('/register', json=register_payload('alice', invite='inv_wrong'))
    assert res.status_code == 400 and 'invite' in res.json['error'].lower()
    make_invite()
    res = client.post('/register', json=register_payload('alice'))
    assert res.status_code == 409
    assert InviteKey.query.one().used_at is None  # failed attempt doesn't burn the invite


def test_register_rejects_invalid_key_material(client, make_invite):
    make_invite()
    payload = register_payload()
    payload['public_key'] = 'bm90IGEga2V5'
    assert client.post('/register', json=payload).status_code == 400
    payload = register_payload()
    payload['wrapped_private_key'] = json.dumps(
        {'salt': 'x', 'iv': 'y', 'data': 'z'}
    )  # old password-wrapped format
    assert client.post('/register', json=payload).status_code == 400
    payload = register_payload(username='Bad Name!')
    assert client.post('/register', json=payload).status_code == 400


# ---------------------------------------------------------------------------
# 6. Revocation
# ---------------------------------------------------------------------------


def test_revoked_user_cannot_list_or_retrieve(
    client, make_client, make_user, make_album, make_media, login
):
    alice, bob = make_user('alice'), make_user('bob')
    album = make_album(alice, title='Holiday', shared_with=[bob])
    media = make_media(album, key_users=[alice, bob])

    bob_client = make_client()
    login(bob_client, 'bob')
    assert bob_client.get(f'/media/{media.id}/raw').status_code == 200
    assert bob_client.get(f'/api/media/{media.id}/key').status_code == 200
    assert b'Holiday' in bob_client.get('/dashboard').data

    login(client, 'alice')
    client.post(f'/{album.id}/remove-user/{bob.id}')

    assert MediaKey.query.filter_by(user_id=bob.id).count() == 0
    assert bob_client.get(f'/media/{media.id}/raw').status_code == 403
    assert bob_client.get(f'/api/media/{media.id}/key').status_code == 403
    assert bob_client.get(f'/album/{album.id}').status_code == 302
    assert b'Holiday' not in bob_client.get('/dashboard').data
    assert bob_client.get(f'/{album.id}/upload').status_code == 302
    assert bob_client.post(f'/api/album/{album.id}/uploads', json={}).status_code == 403
    # owner can no longer hand keys to the removed user either
    res = client.post(
        f'/api/album/{album.id}/share-keys',
        json={
            'user_id': bob.id,
            'keys': [{'media_id': media.id, 'encrypted_key': FAKE_ENCRYPTED_KEY}],
        },
    )
    assert res.status_code == 400
    assert MediaKey.query.filter_by(user_id=bob.id).count() == 0


def test_raw_media_not_cacheable_by_shared_caches(client, make_user, make_album, make_media, login):
    alice = make_user('alice')
    media = make_media(make_album(alice), key_users=[alice])
    login(client, 'alice')
    res = client.get(f'/media/{media.id}/raw')
    assert 'private' in res.headers['Cache-Control']


# ---------------------------------------------------------------------------
# 7. Rate limiting and user-existence protection
# ---------------------------------------------------------------------------


def test_login_rate_limited_per_username(client, make_user, app):
    make_user('alice', 'correct horse')
    limit = app.config['LOGIN_USER_MAX_FAILURES']
    for _ in range(limit):
        assert (
            client.post('/login', json={'username': 'alice', 'auth_key': 'a' * 64}).status_code
            == 401
        )
    res = client.post(
        '/login', json={'username': 'alice', 'auth_key': auth_key_for('alice', 'correct horse')}
    )
    assert res.status_code == 429 and int(res.headers['Retry-After']) > 0


def test_login_rate_limited_per_ip(client, app):
    limit = app.config['LOGIN_IP_MAX_FAILURES']
    for i in range(limit):
        assert (
            client.post('/login', json={'username': f'user{i}', 'auth_key': 'a' * 64}).status_code
            == 401
        )
    assert (
        client.post('/login', json={'username': 'someone', 'auth_key': 'a' * 64}).status_code == 429
    )
    other_ip = client.post(
        '/login',
        json={'username': 'someone', 'auth_key': 'a' * 64},
        environ_base={'REMOTE_ADDR': '10.9.9.9'},
    )
    assert other_ip.status_code == 401


def test_successful_login_resets_username_counter(client, make_user, app):
    make_user('alice', 'correct horse')
    for _ in range(app.config['LOGIN_USER_MAX_FAILURES'] - 1):
        client.post('/login', json={'username': 'alice', 'auth_key': 'a' * 64})
    assert (
        client.post(
            '/login', json={'username': 'alice', 'auth_key': auth_key_for('alice', 'correct horse')}
        ).status_code
        == 200
    )
    assert (
        client.post('/login', json={'username': 'alice', 'auth_key': 'a' * 64}).status_code == 401
    )


def test_unknown_and_wrong_password_look_identical(client, make_user, monkeypatch):
    make_user('alice', 'correct horse')
    import src.routes as routes

    burned = []
    monkeypatch.setattr(routes, 'burn_password_check', lambda v: burned.append(v))
    unknown = client.post('/login', json={'username': 'nobody', 'auth_key': 'a' * 64})
    wrong = client.post('/login', json={'username': 'alice', 'auth_key': 'a' * 64})
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json == wrong.json
    assert burned  # a dummy hash check ran for the unknown user


def test_register_rate_limited(client, app):
    for _ in range(app.config['REGISTER_IP_MAX_FAILURES']):
        assert client.post('/register', json=register_payload(invite='inv_bad')).status_code == 400
    assert client.post('/register', json=register_payload(invite='inv_bad')).status_code == 429


# ---------------------------------------------------------------------------
# 12. JSON validation, field limits, upload/file consistency
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Schema guard (no migrations pre-release), HTTP mode, create-user prompt
# ---------------------------------------------------------------------------


def test_outdated_schema_is_rejected(app):
    from sqlalchemy import text

    from src.app import OutdatedSchemaError, check_schema

    check_schema()
    db.session.execute(text('ALTER TABLE media ADD COLUMN original_filename TEXT'))
    db.session.commit()
    with pytest.raises(OutdatedSchemaError, match='obsolete'):
        check_schema()


def test_session_cookie_secure_can_be_disabled_for_http_testing():
    script = (
        'import os, sys; sys.path.insert(0, sys.argv[1]); '
        'from src.config import ProductionConfig; print(ProductionConfig.SESSION_COOKIE_SECURE)'
    )
    for value, expected in [(None, 'True'), ('false', 'False'), ('true', 'True')]:
        env = {k: v for k, v in os.environ.items() if k != 'SESSION_COOKIE_SECURE'}
        if value is not None:
            env['SESSION_COOKIE_SECURE'] = value
        out = subprocess.run(
            [sys.executable, '-c', script, PROJECT_ROOT],
            env=env,
            capture_output=True,
            text=True,
            check=True,
            cwd='/',
        )
        assert out.stdout.strip() == expected


def test_create_user_reads_password_from_stdin_not_argv(tmp_path):
    env = {**os.environ, 'APP_ENV': 'development', 'DATA_DIR': str(tmp_path)}
    manage = os.path.join(PROJECT_ROOT, 'src', 'manage.py')
    subprocess.run([sys.executable, manage, 'init-db'], capture_output=True, env=env, check=True)
    res = subprocess.run(
        [sys.executable, manage, 'create-user', 'carol', 'secret-on-argv'],
        capture_output=True,
        text=True,
        env=env,
    )
    assert res.returncode == 1 and 'prompted' in res.stderr
    res = subprocess.run(
        [sys.executable, manage, 'create-user', 'carol'],
        input='carol password\n',
        capture_output=True,
        text=True,
        env=env,
    )
    assert res.returncode == 0 and 'created successfully' in res.stdout, res.stdout + res.stderr


def test_data_dir_holds_database_and_uploads(tmp_path):
    """A relative DATA_DIR resolves from the project root; DB + uploads go inside it."""
    script = (
        'import sys, json; sys.path.insert(0, sys.argv[1]); '
        'from src.app import create_app; from src.config import DevelopmentConfig as C; '
        'a = create_app(C); print(json.dumps([C.DATA_DIR, a.instance_path, '
        "a.config['UPLOAD_FOLDER'], a.config['SQLALCHEMY_DATABASE_URI']]))"
    )
    for value, expected in [
        ('run', os.path.join(PROJECT_ROOT, 'run')),
        (str(tmp_path), str(tmp_path)),
    ]:
        env = {**os.environ, 'DATA_DIR': value}
        out = subprocess.run(
            [sys.executable, '-c', script, PROJECT_ROOT],
            env=env,
            cwd='/',
            capture_output=True,
            text=True,
            check=True,
        )
        data_dir, instance, uploads, uri = json.loads(out.stdout)
        assert data_dir == instance == expected
        assert uploads == os.path.join(expected, 'uploads')
        assert uri == 'sqlite:///' + os.path.join(expected, 'secure_gallery.db')


def test_login_session_expires_after_24h(client, make_user, login):
    make_user('alice')
    res = login(client, 'alice')
    cookie = next(h for h in res.headers.getlist('Set-Cookie') if h.startswith('session='))
    assert 'Expires=' in cookie  # permanent session, not a browser-session cookie
    from datetime import datetime, timedelta
    from email.utils import parsedate_to_datetime

    expires = parsedate_to_datetime(cookie.split('Expires=')[1].split(';')[0])
    assert abs(expires - (datetime.now(UTC) + timedelta(hours=24))) < timedelta(minutes=5)


def test_static_assets_are_versioned_by_content(client):
    html = client.get('/login').get_data(as_text=True)
    match = re.search(r'/static/js/e2e-encryption\.js\?v=([0-9a-f]{12})', html)
    assert match
    import hashlib

    with open(os.path.join(PROJECT_ROOT, 'src', 'static', 'js', 'e2e-encryption.js'), 'rb') as f:
        assert match.group(1) == hashlib.sha256(f.read()).hexdigest()[:12]
    assert client.get('/login').get_data(as_text=True).count(match.group(0)) == 1  # stable


def test_sqlite_uses_wal_and_busy_timeout(tmp_path, app):
    from sqlalchemy import create_engine, text

    engine = create_engine(
        f'sqlite:///{tmp_path / "wal.db"}', **app.config['SQLALCHEMY_ENGINE_OPTIONS']
    )
    with engine.connect() as conn:
        assert conn.execute(text('PRAGMA journal_mode')).scalar() == 'wal'
        assert conn.execute(text('PRAGMA busy_timeout')).scalar() == 15000
        assert conn.execute(text('PRAGMA foreign_keys')).scalar() == 1


def test_delete_album_removes_everything(client, make_user, make_album, make_media, login):
    from src.models import Album

    alice, bob = make_user('alice'), make_user('bob')
    album = make_album(alice, shared_with=[bob])
    paths = [
        os.path.join(UPLOAD_DIR, make_media(album, key_users=[alice, bob]).filename)
        for _ in range(2)
    ]
    login(client, 'alice')
    res = client.post(f'/{album.id}/delete')
    assert res.status_code == 302
    assert Album.query.count() == Media.query.count() == MediaKey.query.count() == 0
    assert not any(os.path.exists(p) for p in paths)


def test_manage_help_unknown_and_drop_db(tmp_path):
    env = {**os.environ, 'APP_ENV': 'development', 'DATA_DIR': str(tmp_path)}
    manage = os.path.join(PROJECT_ROOT, 'src', 'manage.py')

    def run(*args, stdin=''):
        return subprocess.run(
            [sys.executable, manage, *args], input=stdin, capture_output=True, text=True, env=env
        )

    help_out = run('help')
    assert (
        help_out.returncode == 0
        and 'drop-db' in help_out.stdout
        and 'create-uploads' not in help_out.stdout
    )
    assert run('no-such-command').returncode == 1

    assert run('init-db').returncode == 0
    (tmp_path / 'uploads' / 'e2e_leftover').write_bytes(b'x')
    assert 'Cancelled' in run('drop-db', stdin='no\n').stdout
    assert (tmp_path / 'uploads' / 'e2e_leftover').exists()
    out = run('drop-db', stdin='yes\n')
    assert out.returncode == 0 and '1 upload file(s) removed' in out.stdout
    assert not (tmp_path / 'uploads' / 'e2e_leftover').exists()


# ---------------------------------------------------------------------------
# Album editing, PWA, theme
# ---------------------------------------------------------------------------


def test_owner_can_rename_album(client, make_user, make_album, login):
    from src.models import Album

    alice = make_user('alice')
    album = make_album(alice, title='Old name')
    login(client, 'alice')
    page = client.get(f'/{album.id}/edit').get_data(as_text=True)
    assert 'value="Old name"' in page
    res = client.post(f'/{album.id}/edit', data={'title': '  New name ', 'description': 'Summer'})
    assert res.status_code == 302
    album = db.session.get(Album, album.id)
    assert (album.title, album.description) == ('New name', 'Summer')
    # empty description is stored as NULL
    client.post(f'/{album.id}/edit', data={'title': 'New name', 'description': ''})
    assert db.session.get(Album, album.id).description is None


def test_rename_validation_keeps_input(client, make_user, make_album, login, app):
    from src.models import Album

    alice = make_user('alice')
    album = make_album(alice, title='Keep')
    login(client, 'alice')
    res = client.post(f'/{album.id}/edit', data={'title': '', 'description': 'typed text'})
    assert res.status_code == 400 and 'typed text' in res.get_data(as_text=True)
    too_long = 'x' * (app.config['MAX_ALBUM_TITLE_LENGTH'] + 1)
    assert client.post(f'/{album.id}/edit', data={'title': too_long}).status_code == 400
    assert db.session.get(Album, album.id).title == 'Keep'


def test_only_owner_can_rename(client, make_user, make_album, login):
    from src.models import Album

    alice, bob = make_user('alice'), make_user('bob')
    album = make_album(alice, title='Mine', shared_with=[bob])
    login(client, 'bob')
    assert client.get(f'/{album.id}/edit').status_code == 302
    client.post(f'/{album.id}/edit', data={'title': 'Hijacked'})
    assert db.session.get(Album, album.id).title == 'Mine'
    # the edit button is only shown to the owner
    assert f'/{album.id}/edit' not in client.get(f'/album/{album.id}').get_data(as_text=True)


def test_web_manifest(client):
    res = client.get('/manifest.webmanifest')
    assert res.status_code == 200 and res.mimetype == 'application/manifest+json'
    manifest = res.get_json()
    assert manifest['display'] == 'standalone' and manifest['start_url'] == '/dashboard'
    sizes = {(i['sizes'], i.get('purpose', 'any')) for i in manifest['icons']}
    assert {('192x192', 'any'), ('512x512', 'any'), ('512x512', 'maskable')} <= sizes
    for icon in manifest['icons']:
        assert client.get(icon['src']).status_code == 200
    assert 'rel="manifest"' in client.get('/login').get_data(as_text=True)


def test_service_worker_served_from_root(client):
    res = client.get('/sw.js')
    assert res.status_code == 200 and res.mimetype == 'text/javascript'
    assert res.headers['Cache-Control'] == 'no-cache'
    body = res.get_data(as_text=True)
    # must not cache anything but versioned static files
    assert "url.pathname.startsWith('/static/') && url.searchParams.has('v')" in body


def test_theme_script_and_toggle_present(client):
    html = client.get('/login').get_data(as_text=True)
    head = html.split('</head>')[0]
    assert 'dataset.theme' in head  # applied before the body renders
    assert 'id="theme-toggle"' in html


def test_dashboard_header_with_create_button(client, make_user, make_album, login):
    make_user('alice')
    login(client, 'alice')
    html = client.get('/dashboard').get_data(as_text=True)
    assert 'My Galleries' not in html
    header = html.split('<div class="section-header">')[1].split('</div>')[0]
    assert 'My Albums' in header and '/create' in header  # also shown when there are no albums yet


def test_fingerprint_unlock_ui_present(client, make_user, login):
    login_html = client.get('/login').get_data(as_text=True)
    assert 'id="device-login"' in login_html and 'deviceUnlock.unlock' in login_html
    make_user('alice')
    login(client, 'alice')
    keys_html = client.get('/account').get_data(as_text=True)
    assert 'id="device-panel"' in keys_html and 'deviceUnlock.enroll' in keys_html
    assert 'id="key-modal-device"' in keys_html  # unlock prompt (base template)


# ---------------------------------------------------------------------------
# Restored: JSON validation, field limits, SECRET_KEY, headers/CSP
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    'body,content_type',
    [
        ('[]', 'application/json'),
        ('"x"', 'application/json'),
        ('{not json', 'application/json'),
        ('{"public_key": "x"}', 'text/plain'),  # force=True used to accept this cross-site
    ],
)
def test_api_rejects_non_object_json(client, make_user, login, body, content_type):
    make_user('alice')
    login(client, 'alice')
    res = client.post('/api/keys/me', data=body, content_type=content_type)
    assert res.status_code == 400
    assert 'error' in res.json


def test_api_rejects_wrong_types(client, make_user, make_album, login):
    alice = make_user('alice')
    album = make_album(alice)
    login(client, 'alice')
    for payload in [
        {'user_id': 'abc', 'keys': [{}]},
        {'user_id': True, 'keys': [{}]},
        {'user_id': alice.id, 'keys': 'nope'},
        {'user_id': alice.id, 'keys': ['nope']},
        {'user_id': alice.id, 'keys': [{'media_id': 1, 'encrypted_key': 123}]},
    ]:
        res = client.post(f'/api/album/{album.id}/share-keys', json=payload)
        assert res.status_code == 400, payload


def test_field_size_limits(client, make_user, login, app):
    make_user('alice')
    login(client, 'alice')
    too_long = 'A' * (app.config['MAX_WRAPPED_PRIVATE_KEY_LENGTH'] + 1)
    assert (
        client.post('/api/keys/me/private', json={'wrapped_private_key': too_long}).status_code
        == 400
    )
    assert (
        client.post(
            '/api/keys/me', json={'public_key': 'A' * 5000, 'wrapped_private_key': wrapped_key_v2()}
        ).status_code
        == 400
    )
    ok = client.post(
        '/api/keys/me',
        json={'public_key': public_key_b64(), 'wrapped_private_key': wrapped_key_v2()},
    )
    assert ok.status_code == 200


def test_delete_media_removes_file_after_commit(client, make_user, make_album, make_media, login):
    alice = make_user('alice')
    album = make_album(alice)
    media = make_media(album, key_users=[alice])
    path = os.path.join(UPLOAD_DIR, media.filename)
    login(client, 'alice')
    client.post(f'/{album.id}/delete-media/{media.id}')
    assert not os.path.exists(path) and Media.query.count() == 0


@pytest.mark.parametrize(
    'value',
    [
        None,
        '',
        'dev-key-change-in-production',
        'change-this-in-production',
        'your-secret-key-here-change-in-production',
        'short',
    ],
)
def test_insecure_secret_keys_rejected(value):
    with pytest.raises(InsecureConfigurationError):
        validate_secret_key(value)


def test_strong_secret_key_accepted():
    validate_secret_key('a' * 64)


def test_production_app_refuses_default_secret_key():
    from src.app import create_app
    from src.config import ProductionConfig

    class Prod(ProductionConfig):
        SECRET_KEY = 'change-this-in-production'

    with pytest.raises(InsecureConfigurationError):
        create_app(Prod)


def test_security_headers_and_csp_nonce(client):
    res = client.get('/login')
    csp = res.headers['Content-Security-Policy']
    nonce = re.search(r"'nonce-([^']+)'", csp).group(1)
    assert "frame-ancestors 'none'" in csp and "object-src 'none'" in csp
    assert 'googleapis' not in res.get_data(as_text=True)
    scripts = re.findall(r'<script[^>]*>', res.get_data(as_text=True))
    assert scripts and all(f'nonce="{nonce}"' in tag for tag in scripts)
    assert res.headers['X-Frame-Options'] == 'DENY'
    assert res.headers['X-Content-Type-Options'] == 'nosniff'
    assert client.get('/login').headers['Content-Security-Policy'] != csp  # fresh nonce per request


def test_templates_have_no_inline_event_handlers():
    templates = os.path.join(PROJECT_ROOT, 'src', 'templates')
    for name in os.listdir(templates):
        with open(os.path.join(templates, name)) as f:
            assert not re.search(r'\son[a-z]+\s*=\s*["\']', f.read()), name


# ---------------------------------------------------------------------------
# Reverse-proxy diagnostics (rate limiting depends on the client IP)
# ---------------------------------------------------------------------------


def _proxy_app(count):
    from src.app import create_app
    from src.config import TestingConfig

    class Config(TestingConfig):
        TRUSTED_PROXY_COUNT = count

    return create_app(Config)


@pytest.mark.parametrize(
    'count,remote,headers,expected',
    [
        (0, '10.0.0.2', {'X-Forwarded-For': '203.0.113.7'}, 'TRUSTED_PROXY_COUNT=0'),
        (1, '203.0.113.7', {}, 'reachable without going through the proxy'),
        (
            2,
            '10.0.0.2',
            {'X-Forwarded-For': '203.0.113.7', 'X-Forwarded-Proto': 'https'},
            'higher than the number',
        ),
        (1, '10.0.0.2', {'X-Forwarded-For': '203.0.113.7'}, 'X-Forwarded-Proto'),
    ],
)
def test_proxy_misconfiguration_is_logged(caplog, count, remote, headers, expected):
    app = _proxy_app(count)
    with caplog.at_level('WARNING'):
        app.test_client().get('/login', headers=headers, environ_base={'REMOTE_ADDR': remote})
        app.test_client().get('/login', headers=headers, environ_base={'REMOTE_ADDR': remote})
    messages = [r.getMessage() for r in caplog.records if expected in r.getMessage()]
    assert len(messages) == 1  # logged once, not per request


def test_correct_proxy_setup_is_quiet_and_uses_client_ip(caplog):
    app = _proxy_app(1)
    seen = {}

    @app.get('/_ip')
    def _ip():
        from flask import request

        seen['ip'], seen['secure'] = request.remote_addr, request.is_secure
        return 'ok'

    headers = {'X-Forwarded-For': '203.0.113.7', 'X-Forwarded-Proto': 'https'}
    with caplog.at_level('WARNING'):
        app.test_client().get('/_ip', headers=headers, environ_base={'REMOTE_ADDR': '10.0.0.2'})
        # container health check: loopback, no proxy headers
        app.test_client().get('/login', environ_base={'REMOTE_ADDR': '127.0.0.1'})
    assert seen == {'ip': '203.0.113.7', 'secure': True}
    assert not [r for r in caplog.records if 'proxy' in r.getMessage().lower()]


# ---------------------------------------------------------------------------
# CSRF protection (disabled in the other tests) and poster/logout hardening
# ---------------------------------------------------------------------------


@pytest.fixture
def csrf_client():
    from src.app import create_app
    from src.config import TestingConfig

    class Config(TestingConfig):
        WTF_CSRF_ENABLED = True

    app = create_app(Config)
    with app.app_context():
        db.create_all()
        user = User(username='alice')
        user.set_auth_key(auth_key_for('alice', 'correct horse'))
        db.session.add(user)
        db.session.commit()
    # Requests run outside this context, each with its own `g` like in production
    # (Flask-WTF caches the token in g; a shared g would hide session changes).
    yield app.test_client()


def _token(client, path='/login'):
    html = client.get(path).get_data(as_text=True)
    return re.search(r'<meta name="csrf-token" content="([^"]+)"', html).group(1)


def test_csrf_required_for_json_login(csrf_client):
    body = {'username': 'alice', 'auth_key': auth_key_for('alice', 'correct horse')}
    res = csrf_client.post('/login', json=body)
    assert res.status_code == 400 and 'CSRF' in res.json['error']
    res = csrf_client.post('/login', json=body, headers={'X-CSRFToken': _token(csrf_client)})
    assert res.status_code == 200


def test_csrf_required_for_forms_and_apis(csrf_client):
    csrf_client.post(
        '/login',
        json={'username': 'alice', 'auth_key': auth_key_for('alice', 'correct horse')},
        headers={'X-CSRFToken': _token(csrf_client)},
    )
    token = _token(csrf_client, '/dashboard')  # new session after login -> new token
    assert csrf_client.post('/create', data={'title': 'No token'}).status_code == 400
    assert csrf_client.post('/create', data={'title': 'Ok', 'csrf_token': token}).status_code == 302
    res = csrf_client.post('/api/keys/me/private', json={'wrapped_private_key': 'x'})
    assert res.status_code == 400 and 'CSRF' in res.json['error']
    assert csrf_client.put('/api/uploads/x?offset=0', data=b'x').status_code == 400


def test_logout_is_post_only_with_token(csrf_client):
    csrf_client.post(
        '/login',
        json={'username': 'alice', 'auth_key': auth_key_for('alice', 'correct horse')},
        headers={'X-CSRFToken': _token(csrf_client)},
    )
    assert csrf_client.get('/logout').status_code == 405  # an <img src="/logout"> does nothing
    assert csrf_client.post('/logout').status_code == 400  # no token
    token = _token(csrf_client, '/dashboard')
    assert csrf_client.post('/logout', data={'csrf_token': token}).status_code == 302
    assert csrf_client.get('/dashboard').status_code == 302  # logged out


def test_every_post_form_carries_a_csrf_token():
    templates = os.path.join(PROJECT_ROOT, 'src', 'templates')
    for name in os.listdir(templates):
        with open(os.path.join(templates, name)) as f:
            html = f.read()
        for form in re.findall(r'<form[^>]*method="POST"[^>]*>(.*?)</form>', html, re.S | re.I):
            if 'novalidate' in form[:0] or name in ('login.html', 'register.html'):
                continue  # submitted by JavaScript (fetch adds the header)
            assert 'csrf_token()' in form, name


def test_account_keys_use_argon2id():
    """Known-answer test: pins the derivation (changing it locks every user out)."""
    from argon2.low_level import Type, hash_secret_raw

    from src.security import ARGON2_LANES, ARGON2_MEMORY_KIB, ARGON2_PASSES

    assert (ARGON2_MEMORY_KIB, ARGON2_PASSES, ARGON2_LANES) == (65536, 3, 1)
    master = hash_secret_raw(
        b'correct horse',
        b'secure-media-gallery|v3|alice',
        time_cost=3,
        memory_cost=65536,
        parallelism=1,
        hash_len=32,
        type=Type.ID,
    )
    keys = derive_account_keys('alice', 'correct horse')
    from src.security import HKDF_SALT, _hkdf_sha256

    assert keys['auth_key_hex'] == _hkdf_sha256(master, HKDF_SALT, b'auth').hex()
    assert keys['auth_key_hex'] != keys['wrap_key_b64']


def test_csp_allows_webassembly_but_not_eval(client):
    csp = client.get('/login').headers['Content-Security-Policy']
    script_src = next(d for d in csp.split('; ') if d.startswith('script-src'))
    assert "'wasm-unsafe-eval'" in script_src and "'unsafe-eval'" not in script_src.replace(
        "'wasm-unsafe-eval'", ''
    )
