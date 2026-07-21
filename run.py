import os
import sys
import ssl
from app import create_app

app = create_app()

SSL_DIR   = os.path.join(os.path.dirname(__file__), "data", "ssl")
CERT_PATH = os.path.join(SSL_DIR, "cert.pem")
KEY_PATH  = os.path.join(SSL_DIR, "key.pem")

HOST = "0.0.0.0"
PORT = 5000


def _has_certs():
    return os.path.exists(CERT_PATH) and os.path.exists(KEY_PATH)


def _run_gunicorn():
    """Launch via gunicorn — proper multi-interface WSGI server.

    Single worker, multiple threads: APScheduler's in-process background jobs
    and the in-memory login rate limiter are only correct if there's exactly
    one process running them. Threads still give real request concurrency for
    this app's I/O-bound workload (DB queries, subprocess calls to nmap that
    release the GIL while waiting).
    """
    threads = os.environ.get("WEB_THREADS", "8")
    args = [
        "gunicorn",
        "--bind", f"{HOST}:{PORT}",
        "--workers", "1",
        "--threads", threads,
        "--timeout", "120",
        "--access-logfile", "-",
        "--error-logfile", "-",
    ]
    if _has_certs():
        args += ["--certfile", CERT_PATH, "--keyfile", KEY_PATH]
        print(f"[PwnBroker] HTTPS  https://{HOST}:{PORT}")
    else:
        print(f"[PwnBroker] WARNING: no TLS cert — running plain HTTP")
        print(f"[PwnBroker] HTTP   http://{HOST}:{PORT}")

    args.append("run:app")

    # Replace current process with gunicorn
    gunicorn_bin = os.path.join(os.path.dirname(sys.executable), "gunicorn")
    os.execv(gunicorn_bin, args)


def _run_dev():
    """Fallback to Flask dev server if gunicorn is unavailable."""
    ctx = None
    if _has_certs():
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CERT_PATH, KEY_PATH)
        print(f"[PwnBroker] HTTPS  https://{HOST}:{PORT}  (dev server)")
    else:
        print(f"[PwnBroker] HTTP   http://{HOST}:{PORT}  (dev server)")
    app.run(host=HOST, port=PORT, debug=False, ssl_context=ctx)


if __name__ == "__main__":
    try:
        import gunicorn  # noqa: F401
        _run_gunicorn()
    except ImportError:
        _run_dev()
