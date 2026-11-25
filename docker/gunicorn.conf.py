# Gunicorn defaults for the container. Override any of them without rebuilding
# via GUNICORN_CMD_ARGS, e.g. "--workers 4 --threads 8" (it takes precedence
# over this file).

bind = '0.0.0.0:5000'
# gthread workers keep sending heartbeats while a request runs, so slow
# requests are not killed by the worker timeout (sync workers would be).
worker_class = 'gthread'
workers = 2
threads = 4
timeout = 60
# Health checks hit /login every 30 s; keep them out of the access log noise.
accesslog = None
