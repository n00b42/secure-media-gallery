"""Content-hashed static URLs (cache until the file changes)."""

import hashlib
import os
from functools import cache

from flask import current_app, url_for


def _file_hash(path):
    with open(path, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()[:12]


_cached_file_hash = cache(_file_hash)


def asset_url(filename, _external=False):
    """URL of a static file with ?v=<content hash>. Re-hashed on every call in debug mode."""
    path = os.path.join(current_app.static_folder, filename)
    version = _file_hash(path) if current_app.debug else _cached_file_hash(path)
    return url_for('static', filename=filename, v=version, _external=_external)
