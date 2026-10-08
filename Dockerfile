# S.A.R.A.H. Companion - small image, no root at run time, nothing to compile (all wheels).
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 DATA_DIR=/data PORT=8080
RUN useradd --system --uid 1000 --create-home sarah && mkdir -p /data && chown sarah /data
WORKDIR /srv
COPY requirements.txt constraints.txt ./
RUN pip install --no-cache-dir -r requirements.txt -c constraints.txt
COPY app ./app
USER sarah
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('PORT','8080'), timeout=4)"
CMD ["python", "-m", "app"]
