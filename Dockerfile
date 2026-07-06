# secure-harness proxy image, with the toolchain baked in so the verify-and-repair loop never
# silently degrades to prompt-only for lack of a compiler/scanner. The model backend is external
# (env SECURE_PROXY_UPSTREAM).
FROM golang:1.26-bookworm
ENV GOTOOLCHAIN=local

RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-venv ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir bandit PyYAML
ENV PATH="/opt/venv/bin:${PATH}"

WORKDIR /app
COPY *.py *.txt *.yaml /app/

EXPOSE 8090
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -sf http://127.0.0.1:8090/v1/models || exit 1
CMD ["python3", "secure_proxy.py", "--port", "8090"]
