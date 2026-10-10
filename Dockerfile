# S.A.R.A.H. Companion - two stages: build in a throw-away stage, run without pip or build tools, never as root.
# Both stages use the SAME base (the venv's python points into it). Dependabot proposes base image updates.
FROM python:3.14-slim-bookworm AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /srv
COPY requirements.txt constraints.txt ./
# http-ece comes as source only (pure Python); everything else as wheels
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install -r requirements.txt -c constraints.txt \
 && /opt/venv/bin/pip uninstall -y pip setuptools wheel \
 && find /opt/venv -name '__pycache__' -prune -exec rm -rf {} +

FROM python:3.14-slim-bookworm
LABEL org.opencontainers.image.title="S.A.R.A.H. Companion" \
      org.opencontainers.image.description="Web-App für die KI-Wächterin der OPNsense (Plugin os-scdeck): Lage, Vorschläge, Aktionen, Push" \
      org.opencontainers.image.source="https://github.com/xruchai86/sarah-companion"
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 DATA_DIR=/data PORT=8080 PATH=/opt/venv/bin:$PATH
RUN useradd --system --uid 1000 --create-home sarah && mkdir -p /data && chown sarah /data \
 && pip uninstall -y pip setuptools wheel 2>/dev/null; rm -rf /root/.cache
COPY --from=build /opt/venv /opt/venv
WORKDIR /srv
COPY app ./app
USER sarah
VOLUME /data
EXPOSE 8080
# HTTPS when a certificate is in /data/tls, otherwise HTTP: app/healthcheck.py tries both
HEALTHCHECK --interval=30s --timeout=8s --start-period=10s --retries=3 CMD ["python", "-m", "app.healthcheck"]
CMD ["python", "-m", "app"]
