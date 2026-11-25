import os
import sqlite3

from flask import Flask
from sqlalchemy import event, inspect
from sqlalchemy.engine import Engine

from src.assets import asset_url

# src.config loads .env itself, before its Config classes read the environment.
from src.config import get_config, validate_secret_key
from src.extensions import csrf, db, login_manager
from src.security import init_security


@event.listens_for(Engine, 'connect')
def _sqlite_pragmas(dbapi_connection, _connection_record):
    """WAL lets readers proceed while one worker writes (gunicorn runs several)."""
    if isinstance(dbapi_connection, sqlite3.Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute('PRAGMA journal_mode=WAL')
        cursor.execute('PRAGMA foreign_keys=ON')
        cursor.close()


def create_app(config_object=None):
    config_object = config_object or get_config()
    # Templates and static files live next to this file (src/templates, src/static).
    # Flask's instance folder IS the data folder, so the app never writes anywhere else.
    app = Flask(__name__, instance_path=config_object.DATA_DIR)
    app.config.from_object(config_object)

    if app.config.get('REQUIRE_STRONG_SECRET_KEY'):
        # Refuse to start with a missing / placeholder key: it would let anyone
        # forge session cookies and log in as any user.
        validate_secret_key(app.config.get('SECRET_KEY'))
        if not app.config.get('SESSION_COOKIE_SECURE'):
            app.logger.warning(
                'SESSION_COOKIE_SECURE is disabled: session cookies are sent over plain HTTP. '
                'Use this only for local testing, never on a reachable server.'
            )

    db.init_app(app)

    login_manager.init_app(app)
    # Every POST/PUT/DELETE needs the session's CSRF token: forms send it as a
    # hidden field, fetch() calls as the X-CSRFToken header (e2e-encryption.js).
    csrf.init_app(app)
    login_manager.login_view = 'auth.login'

    @login_manager.unauthorized_handler
    def unauthorized():
        # Pages redirect to the login page; API calls from an open page get a
        # clear JSON 401 instead of an HTML redirect (e.g. after the idle timeout).
        from flask import jsonify, redirect, request, url_for

        if request.path.startswith('/api/') or request.is_json:
            response = jsonify({'error': 'Your session has expired. Please log in again.'})
            response.status_code = 401
            return response
        return redirect(url_for('auth.login'))

    init_security(app)

    @app.context_processor
    def inject_asset_url():
        return {'asset_url': asset_url}

    from src.routes import album_bp, api_bp, auth_bp, gallery_bp
    from src.uploads import upload_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(gallery_bp)
    app.register_blueprint(album_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(upload_bp)

    from src import sessions

    @login_manager.user_loader
    def load_user(user_id):
        # Only valid with a live server-side session row (revocable per device).
        return sessions.load_user(user_id)

    return app


app = create_app()


class OutdatedSchemaError(RuntimeError):
    pass


def check_schema():
    """Fail loudly if an existing database predates the current models.

    There are no migrations before the first production release: an outdated
    database must be recreated (delete the DB file and the upload folder, then
    run `python src/manage.py init-db`).
    """
    inspector = inspect(db.engine)
    problems = []
    for table in db.metadata.sorted_tables:
        if not inspector.has_table(table.name):
            continue
        existing = {c['name'] for c in inspector.get_columns(table.name)}
        expected = {c.name for c in table.columns}
        if expected - existing:
            problems.append(f'{table.name}: missing {sorted(expected - existing)}')
        if existing - expected:
            problems.append(f'{table.name}: obsolete {sorted(existing - expected)}')
    if problems:
        raise OutdatedSchemaError(
            'Database schema is outdated (' + '; '.join(problems) + '). Pre-release builds '
            'have no migrations: empty the data folder (DATA_DIR), then run '
            '"python src/manage.py init-db".'
        )


def initialize_app_storage():
    """Create runtime directories and initialize/migrate the SQLite schema."""
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)  # also creates DATA_DIR

    with app.app_context():
        db.create_all()
        check_schema()


if __name__ == '__main__':
    # Local run from the project root:  python -m src.app
    initialize_app_storage()
    app.run(debug=False, host='0.0.0.0', port=5000)
