"""Chunked, resumable uploads (src/uploads.py)."""

import os

import pytest
from conftest import (
    CHUNK,
    FAKE_ENCRYPTED_KEY,
    FAKE_NONCE,
    UPLOAD_DIR,
    fake_encrypted_string,
)

from src.extensions import db
from src.models import Media, MediaKey, PendingUpload

STRIDE = CHUNK + 16


def cipher_size(plain_size):
    chunks = max(1, -(-plain_size // CHUNK))
    return plain_size + 16 * chunks


def start(client, album, user_ids, plain_size=0, **overrides):
    body = {
        'file_type': 'image',
        'encrypted_filename': fake_encrypted_string(),
        'encrypted_check': fake_encrypted_string(),
        'nonce_b64': FAKE_NONCE,
        'chunk_size': CHUNK,
        'total_size': cipher_size(plain_size),
        'keys': {str(uid): FAKE_ENCRYPTED_KEY for uid in user_ids},
    }
    body.update(overrides)
    return client.post(f'/api/album/{album.id}/uploads', json=body)


def put(client, token, offset, data):
    return client.put(
        f'/api/uploads/{token}?offset={offset}',
        data=data,
        headers={'Content-Type': 'application/octet-stream'},
    )


def send_all(client, token, total):
    offset = 0
    while offset < total:
        size = min(STRIDE, total - offset)
        res = put(client, token, offset, bytes([offset // STRIDE % 256]) * size)
        assert res.status_code == 200, res.json
        offset = res.json['received']
    return offset


def partial_files():
    folder = os.path.join(UPLOAD_DIR, 'partial')
    return os.listdir(folder) if os.path.isdir(folder) else []


@pytest.fixture
def owner_album(make_user, make_album, login, client):
    alice, bob = make_user('alice'), make_user('bob')
    album = make_album(alice, shared_with=[bob])
    login(client, 'alice')
    return alice, bob, album


def test_full_chunked_upload(client, owner_album):
    alice, bob, album = owner_album
    plain = 2 * CHUNK + 1000  # three chunks, the last one short
    total = cipher_size(plain)
    res = start(client, album, [alice.id, bob.id], plain)
    assert res.status_code == 201
    token = res.json['token']

    assert send_all(client, token, total) == total
    done = client.post(f'/api/uploads/{token}/complete', json={})
    assert done.status_code == 200, done.json

    media = db.session.get(Media, done.json['media_id'])
    assert (media.file_size, media.chunk_size, media.nonce_b64) == (total, CHUNK, FAKE_NONCE)
    assert media.uploaded_by_id == alice.id
    assert os.path.getsize(os.path.join(UPLOAD_DIR, media.filename)) == total
    assert {k.user_id for k in MediaKey.query.filter_by(media_id=media.id)} == {alice.id, bob.id}
    assert PendingUpload.query.count() == 0 and partial_files() == []

    key = client.get(f'/api/media/{media.id}/key').json
    assert (
        key['chunk_size'] == CHUNK and key['file_size'] == total and key['nonce_b64'] == FAKE_NONCE
    )


def test_empty_file_is_one_tag_sized_chunk(client, owner_album):
    alice, _, album = owner_album
    token = start(client, album, [alice.id], 0).json['token']
    assert put(client, token, 0, b'\0' * 16).status_code == 200
    assert client.post(f'/api/uploads/{token}/complete', json={}).status_code == 200


def test_resume_after_interruption(client, owner_album):
    alice, _, album = owner_album
    total = cipher_size(3 * CHUNK)
    token = start(client, album, [alice.id], 3 * CHUNK).json['token']
    assert put(client, token, 0, b'a' * STRIDE).status_code == 200

    # e.g. after a page reload: the browser lists its unfinished uploads ...
    listing = client.get(f'/api/album/{album.id}/uploads').json
    entry = listing['uploads'][0]
    assert entry['token'] == token and entry['received'] == STRIDE
    assert entry['encrypted_key'] == FAKE_ENCRYPTED_KEY  # own key, to recover the file key
    assert entry['encrypted_check']
    # ... and continues from the reported offset
    assert client.get(f'/api/uploads/{token}').json['received'] == STRIDE
    for offset in (STRIDE, 2 * STRIDE):
        assert put(client, token, offset, b'b' * STRIDE).status_code == 200
    assert client.post(f'/api/uploads/{token}/complete', json={}).status_code == 200
    assert Media.query.one().file_size == total


def test_wrong_offset_reports_position(client, owner_album):
    alice, _, album = owner_album
    token = start(client, album, [alice.id], 2 * CHUNK).json['token']
    res = put(client, token, STRIDE, b'x' * STRIDE)
    assert res.status_code == 409 and res.json['received'] == 0
    assert put(client, token, 0, b'x' * STRIDE).status_code == 200
    # a retry of a chunk the server already has is also answered with the position
    res = put(client, token, 0, b'x' * STRIDE)
    assert res.status_code == 409 and res.json['received'] == STRIDE


@pytest.mark.parametrize('size', [STRIDE - 1, STRIDE + 1, 10])
def test_chunk_must_have_exact_size(client, owner_album, size):
    alice, _, album = owner_album
    token = start(client, album, [alice.id], 2 * CHUNK).json['token']
    assert put(client, token, 0, b'x' * size).status_code == 400
    assert client.get(f'/api/uploads/{token}').json['received'] == 0


def test_complete_requires_all_bytes(client, owner_album):
    alice, _, album = owner_album
    token = start(client, album, [alice.id], 2 * CHUNK).json['token']
    put(client, token, 0, b'x' * STRIDE)
    res = client.post(f'/api/uploads/{token}/complete', json={})
    assert res.status_code == 409 and Media.query.count() == 0


@pytest.mark.parametrize(
    'override',
    [
        {'file_type': 'document'},
        {'encrypted_filename': 'holiday.jpg'},  # plaintext name
        {'nonce_b64': 'AAAA'},  # not 8 bytes
        {'chunk_size': 1024},  # below the minimum
        {'total_size': 10},  # smaller than one GCM tag
        {'total_size': STRIDE + 5},  # last chunk shorter than a tag
        {'video_thumbnail': fake_encrypted_string()},  # thumbnail on an image
        {'keys': 'nope'},
    ],
)
def test_start_validation(client, owner_album, override):
    alice, _, album = owner_album
    res = start(client, album, [alice.id], CHUNK, **override)
    assert res.status_code == 400, res.json
    assert PendingUpload.query.count() == 0


def test_start_requires_uploaders_own_key(client, owner_album):
    _, bob, album = owner_album
    assert start(client, album, [bob.id]).status_code == 400


def test_non_member_keys_are_dropped(client, owner_album, make_user):
    alice, _, album = owner_album
    carol = make_user('carol')
    token = start(client, album, [alice.id, carol.id], 0).json['token']
    put(client, token, 0, b'\0' * 16)
    media_id = client.post(f'/api/uploads/{token}/complete', json={}).json['media_id']
    assert MediaKey.query.filter_by(media_id=media_id, user_id=carol.id).count() == 0


def test_video_thumbnail_up_to_limit(client, owner_album, app):
    alice, _, album = owner_album
    thumb = fake_encrypted_string(b'\x07' * 650_000)  # ~870 kB once base64'd
    assert 500_000 < len(thumb) <= app.config['MAX_VIDEO_THUMBNAIL_LENGTH']
    res = start(client, album, [alice.id], CHUNK, file_type='video', video_thumbnail=thumb)
    assert res.status_code == 201


def test_other_users_cannot_touch_an_upload(client, owner_album, make_client, login):
    alice, _, album = owner_album
    token = start(client, album, [alice.id], CHUNK).json['token']
    bob_client = make_client()
    login(bob_client, 'bob')
    assert bob_client.get(f'/api/uploads/{token}').status_code == 404
    assert put(bob_client, token, 0, b'x' * (CHUNK + 16)).status_code == 404
    assert bob_client.post(f'/api/uploads/{token}/complete', json={}).status_code == 404
    assert bob_client.delete(f'/api/uploads/{token}').status_code == 404
    assert bob_client.get(f'/api/album/{album.id}/uploads').json['uploads'] == []


def test_discard_removes_row_and_file(client, owner_album):
    alice, _, album = owner_album
    token = start(client, album, [alice.id], CHUNK).json['token']
    put(client, token, 0, b'x' * (CHUNK + 16))
    assert partial_files() == [f'{token}.part']
    assert client.delete(f'/api/uploads/{token}').status_code == 200
    assert PendingUpload.query.count() == 0 and partial_files() == []


def test_removed_member_loses_unfinished_uploads(client, owner_album, make_client, login):
    alice, bob, album = owner_album
    bob_client = make_client()
    login(bob_client, 'bob')
    token = start(bob_client, album, [alice.id, bob.id], CHUNK).json['token']
    client.post(f'/{album.id}/remove-user/{bob.id}')
    assert db.session.get(PendingUpload, token) is None and partial_files() == []
    assert bob_client.get(f'/api/uploads/{token}').status_code == 404


def test_delete_album_discards_unfinished_uploads(client, owner_album):
    alice, _, album = owner_album
    start(client, album, [alice.id], CHUNK)
    assert client.post(f'/{album.id}/delete').status_code == 302
    assert PendingUpload.query.count() == 0 and partial_files() == []


def test_storage_quota_counts_unfinished_uploads(client, owner_album, app, monkeypatch):
    alice, _, album = owner_album
    monkeypatch.setitem(app.config, 'USER_STORAGE_QUOTA', cipher_size(3 * CHUNK))
    assert start(client, album, [alice.id], 2 * CHUNK).status_code == 201
    res = start(client, album, [alice.id], 2 * CHUNK)
    assert res.status_code == 413 and 'quota' in res.json['error']
    listing = client.get(f'/api/album/{album.id}/uploads').json
    assert listing['used'] == cipher_size(2 * CHUNK) and listing['quota'] == cipher_size(3 * CHUNK)


def test_max_file_size(client, owner_album, app, monkeypatch):
    alice, _, album = owner_album
    monkeypatch.setitem(app.config, 'MAX_FILE_SIZE', CHUNK)
    assert start(client, album, [alice.id], CHUNK).status_code == 201
    assert start(client, album, [alice.id], CHUNK + 1).status_code == 413


def test_low_disk_space_is_refused(client, owner_album, app, monkeypatch):
    alice, _, album = owner_album
    monkeypatch.setitem(app.config, 'MIN_FREE_DISK_SPACE', 1 << 60)
    assert start(client, album, [alice.id], CHUNK).status_code == 507


def test_stale_uploads_expire(client, owner_album, app, monkeypatch):
    from datetime import timedelta

    from src.models import utcnow

    alice, _, album = owner_album
    token = start(client, album, [alice.id], CHUNK).json['token']
    PendingUpload.query.filter_by(token=token).update({'updated_at': utcnow() - timedelta(days=30)})
    db.session.commit()
    client.get(f'/api/album/{album.id}/uploads')
    assert db.session.get(PendingUpload, token) is None and partial_files() == []


def test_requests_are_small_regardless_of_file_size(app):
    # The whole point of chunking: no request carries more than one chunk + metadata.
    assert app.config['MAX_CONTENT_LENGTH'] <= 16 * 1024 * 1024
    assert app.config['MAX_CHUNK_SIZE'] + 16 < app.config['MAX_CONTENT_LENGTH']


def test_raw_media_supports_byte_ranges(client, owner_album):
    alice, _, album = owner_album
    token = start(client, album, [alice.id], 2 * CHUNK).json['token']
    send_all(client, token, cipher_size(2 * CHUNK))
    media_id = client.post(f'/api/uploads/{token}/complete', json={}).json['media_id']
    res = client.get(f'/media/{media_id}/raw', headers={'Range': f'bytes={STRIDE}-{STRIDE + 9}'})
    assert res.status_code == 206 and res.data == bytes([1]) * 10
    assert res.headers['Content-Range'] == f'bytes {STRIDE}-{STRIDE + 9}/{2 * STRIDE}'


def test_failed_completion_keeps_upload_resumable(client, owner_album, monkeypatch):
    alice, _, album = owner_album
    token = start(client, album, [alice.id], CHUNK).json['token']
    send_all(client, token, cipher_size(CHUNK))

    real_commit = db.session.commit

    def boom():
        raise RuntimeError('db down')

    monkeypatch.setattr(db.session, 'commit', boom)
    res = client.post(f'/api/uploads/{token}/complete', json={})
    monkeypatch.setattr(db.session, 'commit', real_commit)
    assert res.status_code == 500
    # no Media row, no stray final file; the partial file is still there to retry
    assert Media.query.count() == 0
    assert [n for n in os.listdir(UPLOAD_DIR) if n.startswith('e2e_')] == []
    assert partial_files() == [f'{token}.part']
    assert client.post(f'/api/uploads/{token}/complete', json={}).status_code == 200
    assert Media.query.count() == 1
