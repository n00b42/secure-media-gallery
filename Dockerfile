# ── Build stage: resolve dependencies with Poetry into a self-contained venv ──
FROM python:3.12-slim AS build

ENV PIP_NO_CACHE_DIR=1 \
    POETRY_VERSION=2.5.2 \
    POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_CREATE=false \
    VIRTUAL_ENV=/opt/venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

RUN pip install "poetry==$POETRY_VERSION" \
    && python -m venv "$VIRTUAL_ENV"

WORKDIR /build
COPY pyproject.toml poetry.lock ./
# Installs into the active venv ($VIRTUAL_ENV) because venv creation is disabled.
RUN poetry install --only main --no-root


# ── Runtime stage: only Python, the venv and the app (no Poetry, no pip cache) ──
FROM python:3.12-slim

LABEL org.opencontainers.image.title="Secure Media Gallery" \
      org.opencontainers.image.description="End-to-end encrypted photo and video albums" \
      org.opencontainers.image.source="https://github.com/n00b42/secure-media-gallery" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

WORKDIR /app
COPY --from=build /opt/venv /opt/venv
COPY src ./src
COPY docker ./docker

# Application code stays owned by root (read-only for the app). The container
# starts as root only so the entrypoint can give /data to PUID:PGID; every app
# process then runs as that user (see docker/run_as.py).
RUN chmod +x docker/entrypoint.sh docker/manage \
    && ln -s /app/docker/manage /usr/local/bin/manage \
    && mkdir -p /data/uploads

# Fixed container layout. All persistent data (database, uploads, generated
# SECRET_KEY) lives in /data. PUID/PGID: owner of the data folder
# (Unraid: 99/100). SECRET_KEY may be left unset: one is generated once.
ENV APP_ENV=production \
    DATA_DIR=/data \
    PUID=1000 \
    PGID=1000

VOLUME /data
EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/login', timeout=4)"

ENTRYPOINT ["/app/docker/entrypoint.sh"]
# Server settings: docker/gunicorn.conf.py (override with GUNICORN_CMD_ARGS).
CMD ["gunicorn", "--config", "/app/docker/gunicorn.conf.py", "src.app:app"]
