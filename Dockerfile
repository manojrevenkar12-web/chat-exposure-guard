# chat-exposure-guard: the API, the alert ticker and the scanners in one image.
FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 CEG_HOME=/app
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid 10001 ceg
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install ".[scanners]"
COPY config ./config
COPY rules ./rules
COPY migrations ./migrations
USER 10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)" || exit 1
ENTRYPOINT ["ceg"]
CMD ["serve", "--port", "8000"]
