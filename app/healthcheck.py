"""Docker HEALTHCHECK: HTTPS when a certificate is in /data/tls, otherwise HTTP - try both. The certificate is for a name, not for
127.0.0.1, so it is not verified here (this only asks: does the app answer?). Exit 0 = healthy."""
import os
import ssl
import sys
import urllib.request

port = os.environ.get("PORT", "8080")
for url, ctx in (("https://127.0.0.1:%s/healthz" % port, ssl._create_unverified_context()), ("http://127.0.0.1:%s/healthz" % port, None)):
    try:
        urllib.request.urlopen(url, timeout=3, context=ctx)
        sys.exit(0)
    except Exception:
        pass
sys.exit(1)
