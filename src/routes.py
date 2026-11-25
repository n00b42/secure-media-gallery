import os

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy.exc import IntegrityError

from src import sessions
from src.assets import asset_url
from src.extensions import db
from src.models import (
    Album,
    InviteKey,
    Media,
    MediaKey,
    PendingUpload,
    User,
    album_shares,
    hash_invite_key,
    utcnow,
)
from src.security import (
    MIN_PASSWORD_LENGTH,
    burn_password_check,
    client_ip_bucket,
    get_int,
    get_str,
    is_valid_auth_key,
    is_valid_encrypted_key,
    is_valid_public_key,
    is_valid_username,
    is_valid_wrapped_private_key,
    json_error,
    json_object,
    normalize_username,
    throttle_clear,
    throttle_record_failure,
    throttle_retry_after,
    too_many_requests,
    username_throttle_key,
)
from src.uploads import discard_pending, storage_info

auth_bp = Blueprint('auth', __name__)
gallery_bp = Blueprint('gallery', __name__)
album_bp = Blueprint('album', __name__)
api_bp = Blueprint('api', __name__, url_prefix='/api')


def cfg(name):
    return current_app.config[name]


# ---------------------------------------------------------------------------
# Access control — the single source of truth for "may this user see this album"
# ---------------------------------------------------------------------------


def is_album_member(album, user_id):
    """True if user_id is the owner or currently in album_shares (EXISTS query)."""
    if album.owner_id == user_id:
        return True
    return db.session.query(
        db.session.query(album_shares)
        .filter(album_shares.c.album_id == album.id, album_shares.c.user_id == user_id)
        .exists()
    ).scalar()


def _album_ids_of(user_id):
    owned = db.session.query(Album.id).filter(Album.owner_id == user_id)
    shared = db.session.query(album_shares.c.album_id).filter(album_shares.c.user_id == user_id)
    return owned.union(shared)


def shares_an_album(user_id, other_id):
    """True if both users are owner or member of at least one common album."""
    mine = {album_id for (album_id,) in _album_ids_of(user_id)}
    return any(album_id in mine for (album_id,) in _album_ids_of(other_id))


def can_access_album(album):
    return is_album_member(album, current_user.id)


def album_member_ids(album):
    rows = db.session.query(album_shares.c.user_id).filter(album_shares.c.album_id == album.id)
    return {album.owner_id, *(user_id for (user_id,) in rows)}


def media_file_path(stored_name):
    """Absolute path of an encrypted blob; only the name is stored in the DB."""
    return os.path.join(cfg('UPLOAD_FOLDER'), os.path.basename(stored_name))


def remove_files(paths):
    """Delete files after the DB commit; a leftover file is harmless, a dangling row is not."""
    for path in paths:
        try:
            if path and os.path.exists(path):
                os.remove(path)
        except OSError:
            current_app.logger.exception(
                'Could not delete file %s (orphan; see manage.py cleanup-orphans)', path
            )


# ---------------------------------------------------------------------------
# Authentication
#
# The browser derives two keys from the password (see src/security.py):
#   auth_key -> sent here, stored as a scrypt hash
#   wrap_key -> stays in the browser, decrypts the private-key backup
# The server never receives the password.
# ---------------------------------------------------------------------------


def login_throttle_rules(username):
    return [
        (
            f'login-ip:{client_ip_bucket()}',
            cfg('LOGIN_IP_MAX_FAILURES'),
            cfg('LOGIN_IP_WINDOW_SECONDS'),
        ),
        (
            username_throttle_key('login-user', username),
            cfg('LOGIN_USER_MAX_FAILURES'),
            cfg('LOGIN_USER_WINDOW_SECONDS'),
        ),
    ]


def register_throttle_rules():
    return [
        (
            f'register-ip:{client_ip_bucket()}',
            cfg('REGISTER_IP_MAX_FAILURES'),
            cfg('REGISTER_IP_WINDOW_SECONDS'),
        ),
    ]


def start_session(user):
    """Sign `user` in with a new server-side session (see src/sessions.py)."""
    session.clear()
    session.permanent = True  # cookie expires with PERMANENT_SESSION_LIFETIME (24 h)
    session[sessions.SESSION_KEY] = sessions.create(user)
    login_user(user)


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        if current_user.is_authenticated:
            return redirect(url_for('gallery.dashboard'))
        return render_template('register.html', min_password_length=MIN_PASSWORD_LENGTH)

    rules = register_throttle_rules()
    retry_after = throttle_retry_after(rules)
    if retry_after:
        return too_many_requests(retry_after)

    data = json_object()
    username = normalize_username(get_str(data, 'username', cfg('MAX_USERNAME_LENGTH')))
    invite_key = get_str(data, 'invite_key', cfg('MAX_INVITE_KEY_LENGTH'))
    auth_key = get_str(data, 'auth_key', 64)
    public_key = get_str(data, 'public_key', cfg('MAX_PUBLIC_KEY_LENGTH'))
    wrapped_private_key = get_str(
        data, 'wrapped_private_key', cfg('MAX_WRAPPED_PRIVATE_KEY_LENGTH')
    )

    if not is_valid_username(username, cfg('MIN_USERNAME_LENGTH'), cfg('MAX_USERNAME_LENGTH')):
        return json_error(
            f'Username must be {cfg("MIN_USERNAME_LENGTH")}-{cfg("MAX_USERNAME_LENGTH")} characters '
            'and contain only a-z, 0-9, ".", "_" or "-".'
        )
    if not is_valid_auth_key(auth_key):
        return json_error('Invalid auth_key format')
    if not is_valid_public_key(public_key, cfg('MAX_PUBLIC_KEY_LENGTH'), cfg('MIN_RSA_KEY_BITS')):
        return json_error('Invalid public key')
    if not is_valid_wrapped_private_key(wrapped_private_key, cfg('MAX_WRAPPED_PRIVATE_KEY_LENGTH')):
        return json_error('Invalid wrapped private key')

    # Check the invite BEFORE the username, so only invite holders can learn
    # whether a username is taken (and they are rate limited too).
    invite = InviteKey.query.filter_by(key_hash=hash_invite_key(invite_key), used_at=None).first()
    if not invite:
        throttle_record_failure(rules)
        return json_error('Invalid or already-used invite key')

    if User.query.filter_by(username=username).first():
        throttle_record_failure(rules)
        return json_error('Username already exists', 409)

    # Claim the invite atomically so two parallel requests cannot both use it.
    claimed = InviteKey.query.filter_by(id=invite.id, used_at=None).update(
        {'used_at': utcnow()}, synchronize_session=False
    )
    if claimed != 1:
        db.session.rollback()
        return json_error('Invalid or already-used invite key')

    user = User(username=username, public_key=public_key, wrapped_private_key=wrapped_private_key)
    user.set_auth_key(auth_key)
    db.session.add(user)
    try:
        db.session.flush()
    except IntegrityError:
        db.session.rollback()
        return json_error('Username already exists', 409)

    InviteKey.query.filter_by(id=invite.id).update(
        {'used_by_user_id': user.id}, synchronize_session=False
    )
    db.session.commit()

    start_session(user)
    flash('Account created — your encryption keys are set up.', 'success')
    return jsonify({'status': 'ok', 'redirect': url_for('gallery.dashboard')})


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        if current_user.is_authenticated:
            return redirect(url_for('gallery.dashboard'))
        return render_template('login.html')

    data = json_object()
    username = normalize_username(get_str(data, 'username', cfg('MAX_USERNAME_LENGTH')))
    auth_key = get_str(data, 'auth_key', 64)
    if not is_valid_auth_key(auth_key):
        return json_error('Invalid auth_key format')

    rules = login_throttle_rules(username)
    retry_after = throttle_retry_after(rules)
    if retry_after:
        return too_many_requests(retry_after)

    user = User.query.filter_by(username=username).first()
    if user is None:
        burn_password_check(auth_key)  # same work as a real check -> no timing oracle
        authenticated = False
    else:
        authenticated = user.check_auth_key(auth_key)

    if not authenticated:
        throttle_record_failure(rules)
        return json_error('Invalid username or password', 401)

    throttle_clear(rules[1][0])
    start_session(user)
    return jsonify({'status': 'ok', 'redirect': url_for('gallery.dashboard')})


@auth_bp.route('/logout', methods=['POST'])
@login_required
def logout():
    """POST only (with CSRF token): a GET logout could be triggered by any image URL."""
    sessions.revoke_current()  # the cookie is useless from now on, even if copied
    logout_user()
    session.clear()
    return redirect(url_for('auth.login'))


# ---------------------------------------------------------------------------
# Public-key API — used by JS for key management and sharing
# ---------------------------------------------------------------------------


@api_bp.route('/keys/me', methods=['POST'])
@login_required
def upload_my_public_key():
    """
    Register / replace the user's key pair. Public key and password-wrapped
    private key are always replaced together so they can never get out of sync.
    Body: { "public_key": "<base64-spki>", "wrapped_private_key": "<v2 JSON>" }
    """
    data = json_object()
    public_key = get_str(data, 'public_key', cfg('MAX_PUBLIC_KEY_LENGTH'))
    wrapped_private_key = get_str(
        data, 'wrapped_private_key', cfg('MAX_WRAPPED_PRIVATE_KEY_LENGTH')
    )

    if not is_valid_public_key(public_key, cfg('MAX_PUBLIC_KEY_LENGTH'), cfg('MIN_RSA_KEY_BITS')):
        return json_error('Invalid public key')
    if not is_valid_wrapped_private_key(wrapped_private_key, cfg('MAX_WRAPPED_PRIVATE_KEY_LENGTH')):
        return json_error('Invalid wrapped private key')

    current_user.public_key = public_key
    current_user.wrapped_private_key = wrapped_private_key
    db.session.commit()
    return jsonify({'status': 'ok'})


@api_bp.route('/keys/<int:user_id>', methods=['GET'])
@login_required
def get_user_public_key(user_id):
    """Return a user's public key so the caller can encrypt a file key for them.

    Only for users who share at least one album with the caller (the only case
    where a key is needed), so user IDs can't be used to list all usernames.
    """
    user = db.session.get(User, user_id)
    if not user or not (user_id == current_user.id or shares_an_album(current_user.id, user_id)):
        return json_error('User not found', 404)
    if not user.public_key:
        return json_error('User has no E2E public key registered', 404)
    return jsonify({'user_id': user_id, 'username': user.username, 'public_key': user.public_key})


@api_bp.route('/keys/me', methods=['GET'])
@login_required
def get_my_public_key():
    """Return current user's registered public key (so JS can verify it matches)."""
    return jsonify(
        {
            'user_id': current_user.id,
            'public_key': current_user.public_key,
            'has_key': current_user.public_key is not None,
            'has_wrapped_private_key': current_user.wrapped_private_key is not None,
        }
    )


@api_bp.route('/keys/me/private', methods=['GET'])
@login_required
def get_my_wrapped_private_key():
    """Return current user's server-side wrapped private key backup (ciphertext)."""
    return jsonify(
        {
            'user_id': current_user.id,
            'has_wrapped_private_key': current_user.wrapped_private_key is not None,
            'wrapped_private_key': current_user.wrapped_private_key,
        }
    )


@api_bp.route('/account/password', methods=['POST'])
@login_required
def change_password():
    """Change the password. The browser derives everything (the server never sees a password):

    current_auth_key     proves the current password (same check as login, same rate limits)
    new_auth_key         stored as the new login credential
    wrapped_private_key  the unchanged private key, re-encrypted with the new password

    All other signed-in devices are signed out.
    """
    data = json_object()
    current_auth_key = get_str(data, 'current_auth_key', 64)
    new_auth_key = get_str(data, 'new_auth_key', 64)
    wrapped = get_str(data, 'wrapped_private_key', cfg('MAX_WRAPPED_PRIVATE_KEY_LENGTH'))
    if not (is_valid_auth_key(current_auth_key) and is_valid_auth_key(new_auth_key)):
        return json_error('Invalid auth key format')
    if not is_valid_wrapped_private_key(wrapped, cfg('MAX_WRAPPED_PRIVATE_KEY_LENGTH')):
        return json_error('Invalid wrapped private key')
    if new_auth_key == current_auth_key:
        return json_error('The new password must be different from the current one')

    rules = login_throttle_rules(current_user.username)
    retry_after = throttle_retry_after(rules)
    if retry_after:
        return too_many_requests(retry_after)
    if not current_user.check_auth_key(current_auth_key):
        throttle_record_failure(rules)
        return json_error('Current password is wrong', 403)

    current_user.set_auth_key(new_auth_key)
    current_user.wrapped_private_key = wrapped
    this_session = sessions.current()
    signed_out = sessions.revoke_others(
        current_user.id, keep_id=this_session.id if this_session else None
    )
    db.session.commit()
    return jsonify({'status': 'ok', 'signed_out': signed_out})


@api_bp.route('/keys/me/private', methods=['POST'])
@login_required
def save_my_wrapped_private_key():
    """Store/update the wrapped private key backup (v2 format only, e.g. after migration)."""
    data = json_object()
    wrapped_private_key = get_str(
        data, 'wrapped_private_key', cfg('MAX_WRAPPED_PRIVATE_KEY_LENGTH')
    )
    if not is_valid_wrapped_private_key(wrapped_private_key, cfg('MAX_WRAPPED_PRIVATE_KEY_LENGTH')):
        return json_error('Invalid wrapped private key')
    if not current_user.public_key:
        return json_error('Register a public key first', 409)

    current_user.wrapped_private_key = wrapped_private_key
    db.session.commit()
    return jsonify({'status': 'ok'})


# ---------------------------------------------------------------------------
# Media key API — per-file encrypted AES keys
# ---------------------------------------------------------------------------


@api_bp.route('/media/<int:media_id>/key', methods=['GET'])
@login_required
def get_media_key(media_id):
    """
    Return the encrypted AES key for this media item addressed to the current user.
    The browser will decrypt it with the user's private RSA key, then use the raw
    AES key to decrypt the file blob.
    """
    media = db.get_or_404(Media, media_id)
    if not can_access_album(media.album):
        return json_error('Forbidden', 403)

    mk = MediaKey.query.filter_by(media_id=media_id, user_id=current_user.id).first()
    if not mk:
        return json_error('No key for this user — sharing may be incomplete', 404)

    return jsonify(
        {
            'media_id': media_id,
            'encrypted_key': mk.encrypted_key,
            'encrypted_filename': media.encrypted_filename,
            'file_type': media.file_type,
            'file_size': media.file_size,
            'nonce_b64': media.nonce_b64,
            'chunk_size': media.chunk_size,
        }
    )


@api_bp.route('/album/<int:album_id>/share-keys', methods=['POST'])
@login_required
def add_share_keys_bulk(album_id):
    """
    Bulk version: owner sends all re-encrypted file keys for a recipient in one request.
    Body: { "user_id": <int>, "keys": [{ "media_id": <int>, "encrypted_key": "<b64>" }, ...] }

    Every media_id must belong to THIS album and the recipient must be a member,
    otherwise the whole request is rejected (nothing is written).
    """
    album = db.get_or_404(Album, album_id)
    if album.owner_id != current_user.id:
        return json_error('Only album owner can share keys', 403)

    data = json_object()
    recipient_id = get_int(data, 'user_id')
    keys = data.get('keys')
    if not isinstance(keys, list) or not keys:
        return json_error('keys must be a non-empty list')
    if len(keys) > cfg('MAX_SHARE_KEYS_PER_REQUEST'):
        return json_error('Too many keys in one request')
    if not is_album_member(album, recipient_id):
        return json_error('Recipient does not have access to this album', 400)

    key_by_media_id = {}
    for entry in keys:
        if not isinstance(entry, dict):
            return json_error('Each key entry must be an object')
        media_id = get_int(entry, 'media_id')
        encrypted_key = entry.get('encrypted_key')
        if not is_valid_encrypted_key(encrypted_key, cfg('MAX_ENCRYPTED_KEY_LENGTH')):
            return json_error(f'Invalid encrypted_key for media {media_id}')
        key_by_media_id[media_id] = encrypted_key

    requested_ids = set(key_by_media_id)
    album_media_ids = {
        media_id
        for (media_id,) in db.session.query(Media.id).filter(
            Media.album_id == album_id, Media.id.in_(requested_ids)
        )
    }
    foreign_ids = requested_ids - album_media_ids
    if foreign_ids:
        return json_error(f'media_id(s) not in this album: {sorted(foreign_ids)}', 400)

    existing_by_media_id = {
        row.media_id: row
        for row in MediaKey.query.filter(
            MediaKey.user_id == recipient_id, MediaKey.media_id.in_(requested_ids)
        )
    }
    for media_id, encrypted_key in key_by_media_id.items():
        row = existing_by_media_id.get(media_id)
        if row:
            row.encrypted_key = encrypted_key
        else:
            db.session.add(
                MediaKey(media_id=media_id, user_id=recipient_id, encrypted_key=encrypted_key)
            )

    db.session.commit()
    return jsonify({'status': 'ok', 'count': len(key_by_media_id)})


@api_bp.route('/album/<int:album_id>/owner-keys', methods=['GET'])
@login_required
def get_owner_keys_for_album(album_id):
    """
    Returns all (media_id, encrypted_key) pairs the current user (owner) has for
    this album, so the browser can re-encrypt them when sharing with a new user.
    """
    album = db.get_or_404(Album, album_id)
    if album.owner_id != current_user.id:
        return json_error('Forbidden', 403)

    rows = (
        db.session.query(MediaKey)
        .join(Media, Media.id == MediaKey.media_id)
        .filter(Media.album_id == album_id, MediaKey.user_id == current_user.id)
        .all()
    )

    return jsonify(
        {
            'album_id': album_id,
            'keys': [{'media_id': r.media_id, 'encrypted_key': r.encrypted_key} for r in rows],
        }
    )


# ---------------------------------------------------------------------------
# Gallery
# ---------------------------------------------------------------------------


@gallery_bp.route('/')
@gallery_bp.route('/dashboard')
@login_required
def dashboard():
    owned_albums = Album.query.filter_by(owner_id=current_user.id).all()
    accessed_albums = current_user.accessed_albums
    return render_template(
        'dashboard.html',
        owned_albums=owned_albums,
        accessed_albums=accessed_albums,
        show_album_previews=current_app.config['ALBUM_OVERVIEW_THUMBNAILS_ENABLED'],
    )


@gallery_bp.route('/manifest.webmanifest')
def web_manifest():
    """Web app manifest: makes the gallery installable as an app (PWA)."""
    icons = [
        {'src': asset_url(f'icons/icon-{size}.png'), 'sizes': f'{size}x{size}', 'type': 'image/png'}
        for size in (192, 512)
    ] + [
        {
            'src': asset_url(f'icons/icon-maskable-{size}.png'),
            'sizes': f'{size}x{size}',
            'type': 'image/png',
            'purpose': 'maskable',
        }
        for size in (192, 512)
    ]
    response = jsonify(
        {
            'id': '/',
            'name': 'Secure Media Gallery',
            'short_name': 'Gallery',
            'description': 'End-to-end encrypted photo and video albums',
            'start_url': url_for('gallery.dashboard'),
            'scope': '/',
            'display': 'standalone',
            'background_color': '#121316',
            'theme_color': '#0f766e',
            'icons': icons,
        }
    )
    response.mimetype = 'application/manifest+json'
    return response


@gallery_bp.route('/sw.js')
def service_worker():
    """Served from the site root (not /static/) so its scope covers the whole site.

    The URL of the shared chunk-crypto script is filled in with its content hash,
    so any change to that script also changes sw.js and updates the worker.
    """
    with open(os.path.join(current_app.static_folder, 'js', 'sw.js'), encoding='utf-8') as f:
        source = f.read().replace('__CHUNKED_FILE_URL__', asset_url('js/chunked-file.js'))
    response = current_app.response_class(source, mimetype='text/javascript')
    # Browsers must always re-check the worker, otherwise updates can get stuck.
    response.headers['Cache-Control'] = 'no-cache'
    return response


@gallery_bp.route('/account')
@login_required
def account():
    """Account page: password, signed-in devices, fingerprint unlock, key fingerprints.

    Fingerprints are computed in the browser from the public keys, so users can
    compare them out-of-band (in person, phone, messenger) to detect key substitution.
    """
    contacts = {}
    for album in list(current_user.albums) + list(current_user.accessed_albums):
        for user in [album.owner, *album.shared_users]:
            if user.id != current_user.id:
                contacts[user.id] = user
    contact_list = sorted(contacts.values(), key=lambda u: u.username)
    this_session = sessions.current()
    devices = [
        {
            'id': row.id,
            'device': sessions.describe_user_agent(row.user_agent),
            'created_at': row.created_at,
            'last_seen_at': row.last_seen_at,
            'current': this_session is not None and row.id == this_session.id,
        }
        for row in sessions.list_for(current_user.id)
    ]
    return render_template(
        'account.html',
        my_public_key=current_user.public_key,
        contacts=[
            {'id': u.id, 'username': u.username, 'public_key': u.public_key} for u in contact_list
        ],
        devices=devices,
        min_password_length=MIN_PASSWORD_LENGTH,
    )


@gallery_bp.route('/account/sessions/<session_id>/revoke', methods=['POST'])
@login_required
def revoke_session(session_id):
    this_session = sessions.current()
    if this_session is not None and session_id == this_session.id:
        flash('Use "Logout" to sign out this browser.', 'info')
    elif sessions.revoke(current_user.id, session_id):
        flash('That device was signed out.', 'success')
    return redirect(url_for('gallery.account'))


@gallery_bp.route('/account/sessions/revoke-others', methods=['POST'])
@login_required
def revoke_other_sessions():
    this_session = sessions.current()
    count = sessions.revoke_others(
        current_user.id, keep_id=this_session.id if this_session else None
    )
    db.session.commit()
    flash(f'Signed out {count} other device(s).', 'success')
    return redirect(url_for('gallery.account'))


@gallery_bp.route('/album/<int:album_id>')
@login_required
def view_album(album_id):
    album = db.get_or_404(Album, album_id)

    if not can_access_album(album):
        flash('You do not have permission to view this album', 'error')
        return redirect(url_for('gallery.dashboard'))

    media = Media.query.filter_by(album_id=album_id).all()
    is_owner = album.owner_id == current_user.id

    return render_template('album.html', album=album, media=media, is_owner=is_owner)


@gallery_bp.route('/media/<int:media_id>/raw')
@login_required
def serve_media_raw(media_id):
    """
    Serve the raw ENCRYPTED file blob to the browser.
    Decryption happens entirely in JavaScript — the server never sees plaintext.
    """
    media = db.get_or_404(Media, media_id)
    if not can_access_album(media.album):
        abort(403)

    path = media_file_path(media.filename)
    if not os.path.exists(path):
        abort(404)

    response = send_file(
        path,
        mimetype='application/octet-stream',
        as_attachment=False,
        conditional=True,
    )
    # Never let shared caches keep a copy; access is re-checked on every request.
    response.headers['Cache-Control'] = 'private, no-cache'
    return response


# ---------------------------------------------------------------------------
# Album management
# ---------------------------------------------------------------------------


def _album_form_values():
    """Validated (title, description) from the album form, or (None, None) after flashing an error."""
    title = (request.form.get('title') or '').strip()
    description = (request.form.get('description') or '').strip()
    if not title:
        flash('Title is required', 'error')
    elif len(title) > cfg('MAX_ALBUM_TITLE_LENGTH'):
        flash(f'Title is too long (max {cfg("MAX_ALBUM_TITLE_LENGTH")} characters)', 'error')
    elif len(description) > cfg('MAX_ALBUM_DESCRIPTION_LENGTH'):
        flash(
            f'Description is too long (max {cfg("MAX_ALBUM_DESCRIPTION_LENGTH")} characters)',
            'error',
        )
    else:
        return title, description or None
    return None, None


def _render_album_form(album=None, title='', description=''):
    return render_template(
        'album_form.html',
        album=album,
        form_title=title,
        form_description=description or '',
        max_title=cfg('MAX_ALBUM_TITLE_LENGTH'),
        max_description=cfg('MAX_ALBUM_DESCRIPTION_LENGTH'),
    )


@album_bp.route('/create', methods=['GET', 'POST'])
@login_required
def create_album():
    if request.method == 'POST':
        title, description = _album_form_values()
        if title is None:
            # Re-show the form with what the user typed instead of losing it.
            return _render_album_form(
                title=request.form.get('title', ''), description=request.form.get('description', '')
            ), 400

        album = Album(title=title, description=description, owner_id=current_user.id)
        db.session.add(album)
        db.session.commit()

        flash('Album created successfully!', 'success')
        return redirect(url_for('gallery.view_album', album_id=album.id))

    return _render_album_form()


@album_bp.route('/<int:album_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_album(album_id):
    """Rename an album / change its description (owner only)."""
    album = db.get_or_404(Album, album_id)
    if album.owner_id != current_user.id:
        flash('You do not have permission to edit this album', 'error')
        return redirect(url_for('gallery.dashboard'))

    if request.method == 'POST':
        title, description = _album_form_values()
        if title is None:
            return _render_album_form(
                album, request.form.get('title', ''), request.form.get('description', '')
            ), 400
        album.title = title
        album.description = description
        db.session.commit()
        flash('Album updated', 'success')
        return redirect(url_for('gallery.view_album', album_id=album.id))

    return _render_album_form(album, album.title, album.description)


@album_bp.route('/<int:album_id>/upload')
@login_required
def upload_media(album_id):
    """Upload page. The files themselves go through the chunked API in src/uploads.py."""
    album = db.get_or_404(Album, album_id)

    if not can_access_album(album):
        flash('You do not have permission to upload to this album', 'error')
        return redirect(url_for('gallery.dashboard'))

    if not current_user.has_e2e_key():
        flash('Your encryption keys are not set up yet. Please wait a moment and refresh.', 'error')
        return redirect(url_for('gallery.view_album', album_id=album_id))

    upload_recipients = [
        {'id': user.id, 'username': user.username, 'public_key': user.public_key}
        for user in [album.owner, *album.shared_users]
        if user.public_key
    ]
    return render_template(
        'upload_media.html',
        album=album,
        upload_recipients=upload_recipients,
        storage=storage_info(album),
    )


@album_bp.route('/<int:album_id>/share', methods=['GET', 'POST'])
@login_required
def share_album(album_id):
    album = db.get_or_404(Album, album_id)

    if album.owner_id != current_user.id:
        flash('You do not have permission to share this album', 'error')
        return redirect(url_for('gallery.dashboard'))

    if request.method == 'POST':
        # Each lookup reveals whether a username exists: limit the unsuccessful ones.
        lookup_rule = [
            (
                f'share-lookup:{current_user.id}',
                cfg('SHARE_LOOKUP_MAX_FAILURES'),
                cfg('SHARE_LOOKUP_WINDOW_SECONDS'),
            )
        ]
        retry_after = throttle_retry_after(lookup_rule)
        if retry_after:
            flash(
                f'Too many unsuccessful lookups. Try again in {-(-retry_after // 60)} minute(s).',
                'error',
            )
            return redirect(url_for('album.share_album', album_id=album_id))

        username = normalize_username(request.form.get('username'))
        user = User.query.filter_by(username=username).first() if username else None

        if not user:
            throttle_record_failure(lookup_rule)
            flash('User not found', 'error')
            return redirect(url_for('album.share_album', album_id=album_id))

        if user.id == current_user.id:
            flash('Cannot share with yourself', 'error')
            return redirect(url_for('album.share_album', album_id=album_id))

        if not user.public_key:
            throttle_record_failure(lookup_rule)
            flash(
                f'{user.username} has not set up E2E encryption yet and cannot receive shared files.',
                'error',
            )
            return redirect(url_for('album.share_album', album_id=album_id))

        if is_album_member(album, user.id):
            flash('Album already shared with this user', 'info')
            return redirect(url_for('album.share_album', album_id=album_id))

        # Add DB share row — the JS layer will handle key re-encryption
        album.shared_users.append(user)
        db.session.commit()

        flash(f'Album shared with {user.username}! Encrypting file keys for them…', 'success')
        return redirect(
            url_for('album.share_album', album_id=album_id, pending_share_user_id=user.id)
        )

    pending_share_user_id = request.args.get('pending_share_user_id', type=int)
    shared_users = album.shared_users
    return render_template(
        'share_album.html',
        album=album,
        shared_users=shared_users,
        shared_user_keys=[
            {'id': u.id, 'username': u.username, 'public_key': u.public_key} for u in shared_users
        ],
        pending_share_user_id=pending_share_user_id,
    )


@album_bp.route('/<int:album_id>/remove-user/<int:user_id>', methods=['POST'])
@login_required
def remove_user_from_album(album_id, user_id):
    """Revoke a user's access.

    After this, every server endpoint (album page, dashboard listing, encrypted
    blob download, file-key API, upload) refuses the user, and their stored file
    keys for this album are deleted. Files or keys they ALREADY downloaded cannot
    be recalled — that is inherent to any E2E system.
    """
    album = db.get_or_404(Album, album_id)

    if album.owner_id != current_user.id:
        flash('You do not have permission', 'error')
        return redirect(url_for('gallery.dashboard'))

    user = db.get_or_404(User, user_id)
    if user in album.shared_users:
        album.shared_users.remove(user)

        for pending in PendingUpload.query.filter_by(album_id=album_id, user_id=user_id):
            discard_pending(pending)
        album_media_ids = db.session.query(Media.id).filter(Media.album_id == album_id)
        MediaKey.query.filter(
            MediaKey.media_id.in_(album_media_ids.scalar_subquery()),
            MediaKey.user_id == user_id,
        ).delete(synchronize_session=False)

        db.session.commit()
        flash(
            f'Removed {user.username}: they can no longer see, list or download anything in this '
            'album, and their file keys were deleted. Copies they already downloaded cannot be recalled.',
            'success',
        )

    return redirect(url_for('album.share_album', album_id=album_id))


@album_bp.route('/<int:album_id>/delete', methods=['POST'])
@login_required
def delete_album(album_id):
    album = db.get_or_404(Album, album_id)

    if album.owner_id != current_user.id:
        flash('You do not have permission', 'error')
        return redirect(url_for('gallery.dashboard'))

    paths = [media_file_path(media.filename) for media in album.media]
    for pending in PendingUpload.query.filter_by(album_id=album_id):
        discard_pending(pending)
    album.shared_users.clear()
    db.session.delete(album)
    db.session.commit()
    remove_files(paths)
    flash('Album deleted successfully', 'success')

    return redirect(url_for('gallery.dashboard'))


@album_bp.route('/<int:album_id>/delete-media/<int:media_id>', methods=['POST'])
@login_required
def delete_media(album_id, media_id):
    album = db.get_or_404(Album, album_id)
    media = db.get_or_404(Media, media_id)

    if album.owner_id != current_user.id or media.album_id != album_id:
        flash('You do not have permission', 'error')
        return redirect(url_for('gallery.dashboard'))

    path = media_file_path(media.filename)
    db.session.delete(media)
    db.session.commit()
    remove_files([path])
    flash('Media deleted successfully', 'success')

    return redirect(url_for('gallery.view_album', album_id=album_id))
