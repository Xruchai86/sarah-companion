import logging
import os
import threading

from cheroot import wsgi
from cheroot.ssl.builtin import BuiltinSSLAdapter

from .main import create_app
from .tls import TLS

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("sarah")


def build(app, port):
    """one server: HTTPS with the watched TLS context when a checked certificate is there, otherwise plain HTTP"""
    srv = wsgi.Server(("0.0.0.0", port), app, numthreads=8, server_name="sarah")
    if TLS.context is not None:
        adapter = BuiltinSSLAdapter(*TLS.pair)
        adapter.context = TLS.context                     # the very context the watcher renews: new connections get a renewed certificate
        srv.ssl_adapter = adapter
    return srv


def serve(app, port):
    TLS.initial()
    stop = threading.Event()
    threading.Thread(target=TLS.watch, args=(stop,), daemon=True, name="tls-watch").start()
    while True:
        srv = build(app, port)
        log.info("listening on port %d (%s)", port, "HTTPS" if TLS.context is not None else "HTTP")
        t = threading.Thread(target=srv.safe_start, daemon=True, name="http")
        t.start()
        TLS.restart.wait()                                # only when the first certificate appears while serving HTTP
        TLS.restart.clear()
        log.info("certificate found: switching to HTTPS")
        srv.stop()
        t.join(10)


if __name__ == "__main__":
    serve(create_app(), int(os.environ.get("PORT", "8080")))
