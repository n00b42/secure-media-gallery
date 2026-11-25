"""Chunked, resumable uploads of browser-encrypted files.

Protocol (all under /api, JSON unless noted):

  POST   /album/<id>/uploads          start: metadata + encrypted file keys -> {token}
  GET    /album/<id>/uploads          my unfinished uploads in this album (for resuming)
  GET    /uploads/<token>             {received, total_size}
  PUT    /uploads/<token>?offset=N    one encrypted chunk (application/octet-stream)
  POST   /uploads/<token>/complete    turn the upload into a Media row
  DELETE /uploads/<token>             discard

The server never sees plaintext. It only checks that the chunk sizes fit the
announced format, so the file can later be served in byte ranges.
"""

import json
import os
import secrets
import shutil
import uuid
from datetime import timedelta

from flask import Blueprint, current_app, jsonify, request, url_for
from flask_login import current_user, login_required
from sqlalchemy import func

from src.extensions import db
from src.models import Album, Media, MediaKey, PendingUpload, utcnow
from src.security import (
    decode_b64,
    get_int,
    get_str,
    is_valid_encrypted_key,
    is_valid_encrypted_string,
    json_error,
    json_object,
)

upload_bp = Blueprint('uploads', __name__, url_prefix='/api')

GCM_TAG = 16
NONCE_BYTES = 8
COPY_BLOCK = 1024 * 1024


def cfg(name):
    return current_app.config[name]


def partial_dir():
    return os.path.join(cfg('UPLOAD_FOLDER'), 'partial')


def partial_path(token):
    return os.path.join(partial_dir(), f'{token}.part')


def chunk_layout(total_size, chunk_size):
    """(chunk_count, plaintext_size) for a ciphertext size, or None if impossible."""
    stride = chunk_size + GCM_TAG
    count = -(-total_size // stride)  # ceil
    last = total_size - (count - 1) * stride
    if count < 1 or last < GCM_TAG:
        return None
    return count, total_size - count * GCM_TAG


def storage_used(owner_id):
    """Bytes counted against a user's quota: everything in the albums they own (also
    files other members uploaded there), plus unfinished uploads into those albums.
    The owner decides who may upload, so the owner's quota pays for it."""
    stored = (
        db.session.query(func.coalesce(func.sum(Media.file_size), 0))
        .join(Album, Album.id == Media.album_id)
        .filter(Album.owner_id == owner_id)
    )
    pending = (
        db.session.query(func.coalesce(func.sum(PendingUpload.total_size), 0))
        .join(Album, Album.id == PendingUpload.album_id)
        .filter(Album.owner_id == owner_id)
    )
    return int(stored.scalar()) + int(pending.scalar())


def storage_info(album):
    """Quota numbers that apply to uploads into `album` (its owner's)."""
    quota = cfg('USER_STORAGE_QUOTA')
    return {
        'used': storage_used(album.owner_id),
        'quota': quota or None,
        'max_file_size': cfg('MAX_FILE_SIZE') or None,
        'own_album': album.owner_id == current_user.id,
    }


def discard_pending(pending):
    """Delete an unfinished upload (row + partial file). Caller commits."""
    path = partial_path(pending.token)
    db.session.delete(pending)
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


def expire_stale_uploads():
    cutoff = utcnow() - timedelta(hours=cfg('UPLOAD_EXPIRY_HOURS'))
    for pending in PendingUpload.query.filter(PendingUpload.updated_at < cutoff).all():
        discard_pending(pending)
    db.session.commit()


def _member_ids(album):
    from src.routes import album_member_ids

    return album_member_ids(album)


def _own_pending(token):
    """The current user's unfinished upload, if they still have access to the album."""
    pending = db.session.get(PendingUpload, token)
    if pending is None or pending.user_id != current_user.id:
        return None, json_error('Upload not found', 404)
    album = db.session.get(Album, pending.album_id)
    if album is None or current_user.id not in _member_ids(album):
        discard_pending(pending)
        db.session.commit()
        return None, json_error('You no longer have access to this album', 403)
    return pending, None


def _pending_json(pending, include_key=False):
    data = {
        'token': pending.token,
        'received': pending.received,
        'total_size': pending.total_size,
        'chunk_size': pending.chunk_size,
        'nonce_b64': pending.nonce_b64,
        'file_type': pending.file_type,
        'encrypted_filename': pending.encrypted_filename,
        'encrypted_check': pending.encrypted_check,
        'created_at': pending.created_at.isoformat(),
    }
    if include_key:
        # The uploader's own encrypted file key: lets the browser recover the key
        # (with the private key) and continue the upload after a page reload.
        data['encrypted_key'] = json.loads(pending.keys_json).get(str(current_user.id))
    return data


@upload_bp.route('/album/<int:album_id>/uploads', methods=['POST'])
@login_required
def start_upload(album_id):
    album = db.get_or_404(Album, album_id)
    members = _member_ids(album)
    if current_user.id not in members:
        return json_error('You do not have permission to upload to this album', 403)
    if not current_user.has_e2e_key():
        return json_error('Your encryption keys are not set up yet', 409)

    data = json_object()
    file_type = get_str(data, 'file_type', 10)
    if file_type not in ('image', 'video'):
        return json_error('file_type must be "image" or "video"')
    encrypted_name = get_str(data, 'encrypted_filename', cfg('MAX_ENCRYPTED_FILENAME_LENGTH'))
    if not is_valid_encrypted_string(encrypted_name, cfg('MAX_ENCRYPTED_FILENAME_LENGTH')):
        return json_error('Invalid encrypted file name')
    check = data.get('encrypted_check') or None
    if check is not None and not is_valid_encrypted_string(check, 1024):
        return json_error('Invalid encrypted_check')
    thumbnail = data.get('video_thumbnail') or None
    if thumbnail is not None and (
        file_type != 'video'
        or not is_valid_encrypted_string(thumbnail, cfg('MAX_VIDEO_THUMBNAIL_LENGTH'))
    ):
        return json_error('Invalid or oversized video thumbnail')

    nonce_b64 = get_str(data, 'nonce_b64', 16)
    nonce = decode_b64(nonce_b64, 16)
    if nonce is None or len(nonce) != NONCE_BYTES:
        return json_error('nonce_b64 must encode 8 bytes')
    chunk_size = get_int(data, 'chunk_size')
    if not cfg('MIN_CHUNK_SIZE') <= chunk_size <= cfg('MAX_CHUNK_SIZE'):
        return json_error('Unsupported chunk_size')
    total_size = get_int(data, 'total_size')
    layout = chunk_layout(total_size, chunk_size)
    if layout is None:
        return json_error('total_size does not match the chunk format')
    plaintext_size = layout[1]
    if cfg('MAX_FILE_SIZE') and plaintext_size > cfg('MAX_FILE_SIZE'):
        return json_error(f'File too large (limit {cfg("MAX_FILE_SIZE")} bytes)', 413)

    raw_keys = data.get('keys')
    if not isinstance(raw_keys, dict):
        return json_error('keys must be an object {user_id: encrypted_key}')
    keys = {}
    for user_id_raw, encrypted_key in raw_keys.items():
        try:
            user_id = int(user_id_raw)
        except (TypeError, ValueError):
            return json_error('Invalid recipient id')
        if user_id not in members:
            continue  # e.g. stale page after a member was removed
        if not is_valid_encrypted_key(encrypted_key, cfg('MAX_ENCRYPTED_KEY_LENGTH')):
            return json_error('Invalid encrypted key')
        keys[str(user_id)] = encrypted_key
    if str(current_user.id) not in keys:
        return json_error("Missing the uploader's own file key")

    expire_stale_uploads()
    quota = cfg('USER_STORAGE_QUOTA')
    if quota and storage_used(album.owner_id) + total_size > quota:
        whose = 'Your' if album.owner_id == current_user.id else "The album owner's"
        return json_error(f'{whose} storage quota is used up', 413)
    os.makedirs(partial_dir(), exist_ok=True)
    free = shutil.disk_usage(partial_dir()).free
    if free - total_size < cfg('MIN_FREE_DISK_SPACE'):
        return json_error('Not enough free disk space on the server', 507)

    pending = PendingUpload(
        token=secrets.token_urlsafe(24),
        album_id=album.id,
        user_id=current_user.id,
        file_type=file_type,
        total_size=total_size,
        received=0,
        nonce_b64=nonce_b64,
        chunk_size=chunk_size,
        encrypted_filename=encrypted_name,
        video_thumbnail_data=thumbnail,
        encrypted_check=check,
        keys_json=json.dumps(keys),
    )
    db.session.add(pending)
    db.session.commit()
    open(partial_path(pending.token), 'wb').close()
    response = jsonify(_pending_json(pending))
    response.status_code = 201
    return response


@upload_bp.route('/album/<int:album_id>/uploads', methods=['GET'])
@login_required
def list_my_uploads(album_id):
    album = db.get_or_404(Album, album_id)
    if current_user.id not in _member_ids(album):
        return json_error('Forbidden', 403)
    expire_stale_uploads()
    rows = PendingUpload.query.filter_by(album_id=album_id, user_id=current_user.id).order_by(
        PendingUpload.created_at
    )
    return jsonify(
        {
            'uploads': [_pending_json(p, include_key=True) for p in rows],
            **storage_info(album),
        }
    )


@upload_bp.route('/uploads/<token>', methods=['GET'])
@login_required
def upload_status(token):
    pending, error = _own_pending(token)
    if error:
        return error
    return jsonify(_pending_json(pending))


@upload_bp.route('/uploads/<token>', methods=['PUT'])
@login_required
def upload_chunk(token):
    """Append exactly one encrypted chunk at ?offset=<bytes received so far>."""
    pending, error = _own_pending(token)
    if error:
        return error

    offset = request.args.get('offset', type=int)
    stride = pending.chunk_size + GCM_TAG
    if offset is None or offset != pending.received:
        return jsonify({'error': 'Offset mismatch', 'received': pending.received}), 409
    if offset % stride or offset >= pending.total_size:
        return json_error('Invalid offset')
    expected = min(stride, pending.total_size - offset)
    if request.content_length != expected:
        return json_error(f'Chunk must be exactly {expected} bytes')

    path = partial_path(token)
    remaining = expected
    with open(path, 'r+b' if os.path.exists(path) else 'wb') as f:
        # A chunk written by an interrupted earlier attempt is simply overwritten.
        f.seek(offset)
        while remaining:
            block = request.stream.read(min(COPY_BLOCK, remaining))
            if not block:
                return json_error('Incomplete chunk')
            f.write(block)
            remaining -= len(block)

    updated = PendingUpload.query.filter_by(token=token, received=offset).update(
        {'received': offset + expected, 'updated_at': utcnow()}, synchronize_session=False
    )
    db.session.commit()
    if updated != 1:  # a concurrent request got there first
        db.session.refresh(pending)
        return jsonify({'error': 'Offset mismatch', 'received': pending.received}), 409
    return jsonify({'received': offset + expected, 'total_size': pending.total_size})


@upload_bp.route('/uploads/<token>/complete', methods=['POST'])
@login_required
def complete_upload(token):
    json_object()  # JSON body required (keeps the endpoint preflight-protected)
    pending, error = _own_pending(token)
    if error:
        return error
    if pending.received != pending.total_size:
        return jsonify({'error': 'Upload incomplete', 'received': pending.received}), 409

    album = db.session.get(Album, pending.album_id)
    members = _member_ids(album)
    keys = {int(k): v for k, v in json.loads(pending.keys_json).items() if int(k) in members}

    part = partial_path(token)
    with open(part, 'r+b') as f:
        f.truncate(pending.total_size)
    stored_name = f'e2e_{uuid.uuid4().hex}'
    final_path = os.path.join(cfg('UPLOAD_FOLDER'), stored_name)

    media = Media(
        album_id=pending.album_id,
        filename=stored_name,
        file_type=pending.file_type,
        file_size=pending.total_size,
        uploaded_by_id=pending.user_id,
        nonce_b64=pending.nonce_b64,
        chunk_size=pending.chunk_size,
        encrypted_filename=pending.encrypted_filename,
        video_thumbnail_data=pending.video_thumbnail_data,
    )
    db.session.add(media)
    db.session.flush()
    for user_id, encrypted_key in keys.items():
        db.session.add(MediaKey(media_id=media.id, user_id=user_id, encrypted_key=encrypted_key))
    db.session.delete(pending)

    os.replace(part, final_path)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        os.replace(final_path, part)  # keep the upload resumable/completable
        current_app.logger.exception('Completing upload %s failed', token)
        return json_error('Could not save the upload; try completing it again.', 500)

    return jsonify(
        {
            'status': 'ok',
            'media_id': media.id,
            'redirect': url_for('gallery.view_album', album_id=media.album_id),
        }
    )


@upload_bp.route('/uploads/<token>', methods=['DELETE'])
@login_required
def discard_upload(token):
    pending = db.session.get(PendingUpload, token)
    if pending is None or pending.user_id != current_user.id:
        return json_error('Upload not found', 404)
    discard_pending(pending)
    db.session.commit()
    return jsonify({'status': 'ok'})
