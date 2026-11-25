#!/usr/bin/env python
"""Utility script for managing the Secure Media Gallery"""

import getpass
import os
import shutil
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.app import app, db, initialize_app_storage
from src.models import (
    Album,
    InviteKey,
    Media,
    PendingUpload,
    User,
    generate_invite_key,
    hash_invite_key,
)
from src.security import (
    MIN_PASSWORD_LENGTH,
    derive_account_keys,
    is_valid_username,
    normalize_username,
)
from src.uploads import expire_stale_uploads, storage_used


def init_db():
    """Initialize the database"""
    print('Initializing database...')
    initialize_app_storage()
    print('✓ Database initialized successfully!')
    print(f'✓ Data folder:   {app.config["DATA_DIR"]}')
    print(f'✓ Database:      {app.config["SQLALCHEMY_DATABASE_URI"]}')
    print(f'✓ Uploads:       {app.config["UPLOAD_FOLDER"]}')


def drop_db():
    """Delete ALL data: drop every table and remove the encrypted uploads."""
    folder = app.config['UPLOAD_FOLDER']
    print(f'This deletes every table in {app.config["SQLALCHEMY_DATABASE_URI"]}')
    print(f'and every encrypted file in {folder}.')
    if input("Type 'yes' to confirm: ").strip().lower() != 'yes':
        print('Cancelled')
        return
    with app.app_context():
        db.drop_all()
    removed = 0
    if os.path.isdir(folder):
        for name in os.listdir(folder):
            if name.startswith('e2e_'):
                os.remove(os.path.join(folder, name))
                removed += 1
    shutil.rmtree(os.path.join(folder, 'partial'), ignore_errors=True)  # unfinished uploads
    print(f"✓ Database dropped, {removed} upload file(s) removed. Run 'init-db' to start over.")


def read_new_password():
    """Prompt for a password without echo (never via argv: it would end up in
    shell history and be visible to other users in the process list).
    When stdin is not a terminal (automation), one line is read from stdin."""
    if not sys.stdin.isatty():
        return sys.stdin.readline().rstrip('\n')
    password = getpass.getpass('Password: ')
    if password != getpass.getpass('Repeat password: '):
        print('✗ Passwords do not match')
        sys.exit(1)
    return password


def create_user(username, password):
    """Create a user. Their key pair is generated in the browser on first login."""
    username = normalize_username(username)
    if not is_valid_username(
        username, app.config['MIN_USERNAME_LENGTH'], app.config['MAX_USERNAME_LENGTH']
    ):
        sys.exit("✗ Username must be 3-80 characters: a-z, 0-9, '.', '_', '-'")
    if len(password) < MIN_PASSWORD_LENGTH:
        sys.exit(f'✗ Password must be at least {MIN_PASSWORD_LENGTH} characters')

    with app.app_context():
        if User.query.filter_by(username=username).first():
            sys.exit(f"✗ User '{username}' already exists")

        user = User(username=username)
        # Same derivation the browser performs; only the auth key's hash is stored.
        user.set_auth_key(derive_account_keys(username, password)['auth_key_hex'])
        db.session.add(user)
        db.session.commit()
        print(f"✓ User '{username}' created successfully")


def cleanup_orphans(delete=False):
    """Find encrypted blobs without a DB row (and DB rows whose blob is missing)."""
    with app.app_context():
        expire_stale_uploads()  # unfinished uploads older than UPLOAD_EXPIRY_HOURS
        partial = os.path.join(app.config['UPLOAD_FOLDER'], 'partial')
        tokens = {p.token for p in PendingUpload.query.all()}
        stray = sorted(
            name
            for name in (os.listdir(partial) if os.path.isdir(partial) else [])
            if name.removesuffix('.part') not in tokens
        )
        print(f'Partial upload files without an upload in progress: {len(stray)}')
        for name in stray:
            path = os.path.join(partial, name)
            if delete:
                os.remove(path)
                print(f'  deleted {path}')
            else:
                print(f'  {path}')

        folder = app.config['UPLOAD_FOLDER']
        media_rows = Media.query.all()
        referenced = {m.filename for m in media_rows}
        on_disk = {
            name
            for name in (os.listdir(folder) if os.path.isdir(folder) else [])
            if name.startswith('e2e_') and os.path.isfile(os.path.join(folder, name))
        }

        orphans = sorted(on_disk - referenced)
        print(f'Orphaned files (no DB row): {len(orphans)}')
        for name in orphans:
            path = os.path.join(folder, name)
            if delete:
                os.remove(path)
                print(f'  deleted {path}')
            else:
                print(f'  {path}')
        if orphans and not delete:
            print("Run 'cleanup-orphans --delete' to remove them.")

        missing = [m for m in media_rows if not os.path.exists(os.path.join(folder, m.filename))]
        print(f'DB rows with missing file: {len(missing)}')
        for m in missing:
            print(f'  media id={m.id} album={m.album_id} file={m.filename}')


def create_invite(count=1):
    """Create one or more invite keys"""
    with app.app_context():
        print('Generated invite key(s):')
        for _ in range(count):
            raw_key = generate_invite_key()
            key_hash = hash_invite_key(raw_key)

            db.session.add(InviteKey(key_hash=key_hash))
            print(f'  {raw_key}')

        db.session.commit()


def ensure_invite():
    """First start: if there are no users and no unused invite, create one and print it.

    Lets container users (e.g. on Unraid) register the first account straight
    from the container log, without a shell.
    """
    with app.app_context():
        if User.query.count() or InviteKey.query.filter_by(used_at=None).count():
            return
        raw_key = generate_invite_key()
        db.session.add(InviteKey(key_hash=hash_invite_key(raw_key)))
        db.session.commit()
        print('=' * 64)
        print(' No accounts yet. Register the first one with this invite key:')
        print(f'   {raw_key}')
        print(' More invites: manage create-invite   (in the container)')
        print('=' * 64)


def list_users():
    """List all users"""
    with app.app_context():
        users = User.query.all()
        if not users:
            print('No users found')
            return

        print('\nUsers:')
        print('-' * 50)
        for user in users:
            print(f'ID: {user.id} | Username: {user.username}')
        print('-' * 50)


def stats():
    """Show database statistics"""
    with app.app_context():
        user_count = User.query.count()
        album_count = Album.query.count()
        media_count = Media.query.count()

        print('\n📊 Database Statistics:')
        print(f'  Users: {user_count}')
        print(f'  Albums: {album_count}')
        print(f'  Media Files: {media_count}')
        print(f'  Unfinished uploads: {PendingUpload.query.count()}')
        quota = app.config['USER_STORAGE_QUOTA']
        print(
            f'\n💾 Storage per album owner (quota: {human_size(quota) if quota else "unlimited"}):'
        )
        for user in User.query.order_by(User.username):
            print(f'  {user.username:<20} {human_size(storage_used(user.id))}')
        print()


def human_size(value):
    for unit in ('B', 'KiB', 'MiB', 'GiB', 'TiB'):
        if value < 1024 or unit == 'TiB':
            return f'{value:.0f} {unit}' if unit == 'B' else f'{value:.1f} {unit}'
        value /= 1024


USAGE = """Secure Media Gallery management

Usage: python src/manage.py <command> [args]

Commands:
  init-db                    Create the data folder and database tables
  create-invite [count]      Generate invite key(s) for registration
  ensure-invite              Print a first invite key if there are no users yet
  create-user <username>     Create a user (password is prompted)
  list-users                 List all users
  stats                      Show counts of users, albums and media
  cleanup-orphans [--delete] Report (or delete) upload files without a DB row
  drop-db                    Delete ALL data: tables and encrypted uploads
  help                       Show this help
"""


def main(argv):
    command, args = (argv[0], argv[1:]) if argv else ('help', [])

    if command in ('help', '-h', '--help'):
        print(USAGE)
    elif command == 'init-db':
        init_db()
    elif command == 'create-invite':
        try:
            count = int(args[0]) if args else 1
        except ValueError:
            count = 0
        if count < 1:
            sys.exit('Usage: python src/manage.py create-invite [count]   (count >= 1)')
        create_invite(count)
    elif command == 'ensure-invite':
        ensure_invite()
    elif command == 'create-user':
        if len(args) != 1:
            sys.exit('Usage: python src/manage.py create-user <username>   (password is prompted)')
        create_user(args[0], read_new_password())
    elif command == 'list-users':
        list_users()
    elif command == 'stats':
        stats()
    elif command == 'cleanup-orphans':
        cleanup_orphans(delete='--delete' in args)
    elif command == 'drop-db':
        drop_db()
    else:
        print(USAGE, file=sys.stderr)
        sys.exit(f'Unknown command: {command}')


if __name__ == '__main__':
    main(sys.argv[1:])
