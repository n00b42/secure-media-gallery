"""Server-side login sessions: revocable per browser ("signed-in devices")."""

import hashlib
import secrets
from datetime import timedelta

from flask import current_app, request, session

from src.extensions import db
from src.models import User, UserSession, utcnow

SESSION_KEY = 'sid'
TOUCH_INTERVAL = timedelta(minutes=5)  # how often last_seen_at is written


def _hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def create(user):
    """Start a new session row for `user`; returns the token for the cookie."""
    now = utcnow()
    UserSession.query.filter(
        (UserSession.expires_at < now)
        | (UserSession.last_seen_at < now - current_app.config['SESSION_IDLE_TIMEOUT'])
    ).delete(synchronize_session=False)
    token = secrets.token_urlsafe(32)
    db.session.add(
        UserSession(
            id=secrets.token_urlsafe(12),
            token_hash=_hash(token),
            user_id=user.id,
            created_at=now,
            last_seen_at=now,
            expires_at=now + current_app.config['PERMANENT_SESSION_LIFETIME'],
            user_agent=(request.user_agent.string or '')[:200] or None,
        )
    )
    db.session.commit()
    return token


def current():
    """The UserSession of this request, if its cookie is valid and not expired."""
    token = session.get(SESSION_KEY)
    if not token:
        return None
    row = UserSession.query.filter_by(token_hash=_hash(token)).first()
    if row is None or row.expires_at <= utcnow():
        return None
    return row


def is_live(row, now=None):
    """Neither expired nor idle for longer than SESSION_IDLE_TIMEOUT."""
    now = now or utcnow()
    return (
        row.expires_at > now
        and now - row.last_seen_at <= current_app.config['SESSION_IDLE_TIMEOUT']
    )


def load_user(user_id):
    """Flask-Login user loader: the user only counts as logged in with a live session row."""
    row = current()
    if row is None or str(row.user_id) != str(user_id):
        session.clear()  # revoked, expired or tampered: drop the stale cookie
        return None
    now = utcnow()
    if now - row.last_seen_at > current_app.config['SESSION_IDLE_TIMEOUT']:
        db.session.delete(row)  # idle for too long
        db.session.commit()
        session.clear()
        return None
    if now - row.last_seen_at > TOUCH_INTERVAL:
        row.last_seen_at = now
        db.session.commit()
    return db.session.get(User, row.user_id)


def revoke_current():
    row = current()
    if row is not None:
        db.session.delete(row)
        db.session.commit()


def revoke(user_id, session_id):
    """Sign out one of the user's sessions. Returns True if it existed."""
    deleted = UserSession.query.filter_by(user_id=user_id, id=session_id).delete(
        synchronize_session=False
    )
    db.session.commit()
    return deleted == 1


def revoke_others(user_id, keep_id=None):
    """Sign out all of the user's sessions except `keep_id`. Returns how many. Caller commits."""
    query = UserSession.query.filter(UserSession.user_id == user_id)
    if keep_id is not None:
        query = query.filter(UserSession.id != keep_id)
    return query.delete(synchronize_session=False)


def list_for(user_id):
    rows = (
        UserSession.query.filter(UserSession.user_id == user_id, UserSession.expires_at > utcnow())
        .order_by(UserSession.last_seen_at.desc())
        .all()
    )
    return [row for row in rows if is_live(row)]


def describe_user_agent(ua):
    """'Firefox on Linux' style summary for the device list (best effort)."""
    ua = ua or ''
    browser = next(
        (
            name
            for pattern, name in (
                ('Edg/', 'Edge'),
                ('OPR/', 'Opera'),
                ('Firefox/', 'Firefox'),
                ('Chrome/', 'Chrome'),
                ('Chromium/', 'Chromium'),
                ('Safari/', 'Safari'),
            )
            if pattern in ua
        ),
        'Unknown browser',
    )
    system = next(
        (
            name
            for pattern, name in (
                ('Android', 'Android'),
                ('iPhone', 'iPhone'),
                ('iPad', 'iPad'),
                ('Windows', 'Windows'),
                ('Mac OS X', 'macOS'),
                ('CrOS', 'ChromeOS'),
                ('Linux', 'Linux'),
            )
            if pattern in ua
        ),
        'unknown system',
    )
    return f'{browser} on {system}'
