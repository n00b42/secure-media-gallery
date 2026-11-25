"""Sessions (signed-in devices), password change, public-key visibility, share
lookup limits and album-owner storage quotas."""

import hashlib

import pytest
from conftest import (
    FAKE_ENCRYPTED_KEY,
    FAKE_NONCE,
    auth_key_for,
    fake_encrypted_string,
    wrapped_key_v2,
)

from src.extensions import db
from src.models import User, UserSession


def session_cookie(client):
    return client.get_cookie('session').value


# ---------------------------------------------------------------------------
# Server-side sessions
# ---------------------------------------------------------------------------


def test_login_creates_a_revocable_session(client, make_user, login):
    make_user('alice')
    login(client, 'alice')
    row = UserSession.query.one()
    assert row.user_agent is not None and len(row.token_hash) == 64
    assert client.get('/dashboard').status_code == 200


def test_logout_kills_copied_cookie(app, client, make_user, login):
    make_user('alice')
    login(client, 'alice')
    stolen = session_cookie(client)
    client.post('/logout')
    assert UserSession.query.count() == 0

    thief = app.test_client()
    thief.set_cookie('session', stolen)
    assert thief.get('/dashboard').status_code == 302  # signed cookie is valid, session is not


def test_revoke_one_device_and_all_others(app, make_user, login):
    make_user('alice')
    phone, laptop, tablet = app.test_client(), app.test_client(), app.test_client()
    for c in (phone, laptop, tablet):
        login(c, 'alice')
    assert UserSession.query.count() == 3

    page = laptop.get('/account').get_data(as_text=True)
    assert page.count('class="session-item"') == 3 and 'this browser' in page

    phone_hash = hashlib.sha256(_token_of(app, phone).encode()).hexdigest()
    phone_id = UserSession.query.filter_by(token_hash=phone_hash).one().id
    laptop.post(f'/account/sessions/{phone_id}/revoke')
    assert phone.get('/dashboard').status_code == 302
    assert laptop.get('/dashboard').status_code == 200

    laptop.post('/account/sessions/revoke-others')
    assert tablet.get('/dashboard').status_code == 302
    assert laptop.get('/dashboard').status_code == 200
    assert UserSession.query.count() == 1


def _token_of(app, client):
    serializer = app.session_interface.get_signing_serializer(app)
    return serializer.loads(session_cookie(client))['sid']


def test_cannot_revoke_someone_elses_session(app, make_user, login):
    make_user('alice'), make_user('bob')
    alice, bob = app.test_client(), app.test_client()
    login(alice, 'alice'), login(bob, 'bob')
    bob_session = UserSession.query.filter_by(
        user_id=User.query.filter_by(username='bob').one().id
    ).one()
    alice.post(f'/account/sessions/{bob_session.id}/revoke')
    assert bob.get('/dashboard').status_code == 200


def test_expired_session_is_rejected(client, make_user, login):
    from datetime import timedelta

    from src.models import utcnow

    make_user('alice')
    login(client, 'alice')
    UserSession.query.update({'expires_at': utcnow() - timedelta(seconds=1)})
    db.session.commit()
    assert client.get('/dashboard').status_code == 302


# ---------------------------------------------------------------------------
# Password change
# ---------------------------------------------------------------------------


def change(client, current='correct horse', new='new password!', wrapped=None):
    return client.post(
        '/api/account/password',
        json={
            'current_auth_key': auth_key_for('alice', current),
            'new_auth_key': auth_key_for('alice', new),
            'wrapped_private_key': wrapped or wrapped_key_v2(),
        },
    )


def test_password_change(app, make_user, login):
    make_user('alice')
    this_tab, other_device = app.test_client(), app.test_client()
    login(this_tab, 'alice'), login(other_device, 'alice')
    new_wrapped = wrapped_key_v2().replace('"v": 2', '"v": 2 ')

    res = change(this_tab, wrapped=new_wrapped)
    assert res.status_code == 200 and res.json['signed_out'] == 1
    assert this_tab.get('/dashboard').status_code == 200  # current session kept
    assert other_device.get('/dashboard').status_code == 302  # others signed out
    assert User.query.one().wrapped_private_key == new_wrapped

    fresh = app.test_client()
    assert login(fresh, 'alice', 'correct horse').status_code == 401
    assert login(fresh, 'alice', 'new password!').status_code == 200


def test_password_change_wrong_current_is_rate_limited(app, client, make_user, login):
    make_user('alice')
    login(client, 'alice')
    for _ in range(app.config['LOGIN_USER_MAX_FAILURES']):
        assert change(client, current='wrong guess').status_code == 403
    assert change(client).status_code == 429  # even with the right password now
    assert User.query.one().check_auth_key(auth_key_for('alice', 'correct horse'))


@pytest.mark.parametrize(
    'override',
    [
        {'new_auth_key': 'short'},
        {'wrapped_private_key': '{"salt": "x"}'},
        {'new_auth_key': auth_key_for('alice', 'correct horse')},  # unchanged
    ],
)
def test_password_change_validation(client, make_user, login, override):
    make_user('alice')
    login(client, 'alice')
    body = {
        'current_auth_key': auth_key_for('alice', 'correct horse'),
        'new_auth_key': auth_key_for('alice', 'new password!'),
        'wrapped_private_key': wrapped_key_v2(),
        **override,
    }
    assert client.post('/api/account/password', json=body).status_code == 400


# ---------------------------------------------------------------------------
# Public keys only for people you share an album with
# ---------------------------------------------------------------------------


def test_public_keys_only_for_album_partners(client, make_user, make_album, login):
    alice, bob, carol = make_user('alice'), make_user('bob'), make_user('carol')
    make_album(alice, shared_with=[bob])
    login(client, 'alice')
    assert client.get(f'/api/keys/{alice.id}').status_code == 200  # self
    assert client.get(f'/api/keys/{bob.id}').json['username'] == 'bob'  # shares an album
    res = client.get(f'/api/keys/{carol.id}')
    assert res.status_code == 404 and 'carol' not in res.get_data(as_text=True)
    assert client.get('/api/keys/999').status_code == 404  # same answer as a stranger


def test_album_partner_via_someone_elses_album(client, make_user, make_album, login):
    alice, bob, carol = make_user('alice'), make_user('bob'), make_user('carol')
    make_album(carol, shared_with=[alice, bob])  # alice and bob are both members
    login(client, 'alice')
    assert client.get(f'/api/keys/{bob.id}').status_code == 200


def test_share_lookups_are_rate_limited(app, client, make_user, make_album, login):
    alice = make_user('alice')
    make_user('bob')
    album = make_album(alice)
    login(client, 'alice')
    for i in range(app.config['SHARE_LOOKUP_MAX_FAILURES']):
        page = client.post(
            f'/{album.id}/share', data={'username': f'guess{i}'}, follow_redirects=True
        )
        assert 'User not found' in page.get_data(as_text=True)
    page = client.post(f'/{album.id}/share', data={'username': 'bob'}, follow_redirects=True)
    assert 'Too many unsuccessful lookups' in page.get_data(as_text=True)
    from src.models import Album

    assert db.session.get(Album, album.id).shared_users == []


def test_successful_shares_do_not_count(app, client, make_user, make_album, login):
    alice = make_user('alice')
    album_ids = [make_album(alice, title=f'a{i}').id for i in range(3)]
    make_user('bob')
    login(client, 'alice')
    for _ in range(app.config['SHARE_LOOKUP_MAX_FAILURES'] - 1):
        client.post(f'/{album_ids[0]}/share', data={'username': 'nobody'})
    for album_id in album_ids:
        page = client.post(f'/{album_id}/share', data={'username': 'bob'}, follow_redirects=True)
        assert 'Album shared with bob' in page.get_data(as_text=True)


# ---------------------------------------------------------------------------
# Storage quota: uploads count against the album owner
# ---------------------------------------------------------------------------


def start_upload(client, album, user_ids, total):
    return client.post(
        f'/api/album/{album.id}/uploads',
        json={
            'file_type': 'image',
            'encrypted_filename': fake_encrypted_string(),
            'nonce_b64': FAKE_NONCE,
            'chunk_size': 64 * 1024,
            'total_size': total,
            'keys': {str(uid): FAKE_ENCRYPTED_KEY for uid in user_ids},
        },
    )


def test_member_uploads_count_against_album_owner(app, make_user, make_album, login, monkeypatch):
    alice, bob = make_user('alice'), make_user('bob')
    album = make_album(alice, shared_with=[bob])
    bobs_own = make_album(bob)
    monkeypatch.setitem(app.config, 'USER_STORAGE_QUOTA', 100_000)
    bob_client = app.test_client()
    login(bob_client, 'bob')

    assert start_upload(bob_client, album, [alice.id, bob.id], 60_000).status_code == 201
    res = start_upload(bob_client, album, [alice.id, bob.id], 60_000)
    assert res.status_code == 413 and "album owner's" in res.json['error']
    # bob's own quota is untouched by what he uploaded into alice's album
    assert start_upload(bob_client, bobs_own, [bob.id], 60_000).status_code == 201

    info = bob_client.get(f'/api/album/{album.id}/uploads').json
    assert info['used'] == 60_000 and info['own_album'] is False


# ---------------------------------------------------------------------------
# Idle timeout
# ---------------------------------------------------------------------------


def _idle(minutes):
    from datetime import timedelta

    from src.models import utcnow

    UserSession.query.update({'last_seen_at': utcnow() - timedelta(minutes=minutes)})
    db.session.commit()


def test_idle_session_ends_after_two_hours(app, client, make_user, login):
    from datetime import timedelta

    assert app.config['SESSION_IDLE_TIMEOUT'] == timedelta(hours=2)
    make_user('alice')
    login(client, 'alice')
    _idle(119)
    assert client.get('/dashboard').status_code == 200  # still within the limit (and refreshed)
    _idle(121)
    assert client.get('/dashboard').status_code == 302
    assert UserSession.query.count() == 0


def test_activity_keeps_the_session_alive(client, make_user, login):
    make_user('alice')
    login(client, 'alice')
    _idle(100)
    client.get('/dashboard')  # activity: last_seen_at is refreshed
    _idle_since = UserSession.query.one().last_seen_at
    from src.models import utcnow

    assert (utcnow() - _idle_since).total_seconds() < 60


def test_expired_session_api_answers_401_json(client, make_user, login):
    make_user('alice')
    login(client, 'alice')
    _idle(121)
    res = client.get('/api/keys/me')
    assert res.status_code == 401 and 'expired' in res.json['error']


def test_idle_sessions_are_not_listed(app, make_user, login):
    make_user('alice')
    old, current = app.test_client(), app.test_client()
    login(old, 'alice')
    _idle(130)
    login(current, 'alice')
    page = current.get('/account').get_data(as_text=True)
    assert page.count('class="session-item"') == 1
