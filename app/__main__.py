import logging
import os

from waitress import serve

from .main import create_app

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s %(message)s")
app = create_app()
serve(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8080")), threads=8, ident="sarah")
