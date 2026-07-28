# secure-harness proxy image, with the toolchain baked in so the verify-and-repair loop never
# silently degrades to prompt-only for lack of a compiler/scanner. The model backend is external
# (env SECURE_PROXY_UPSTREAM).
FROM golang:1.26-bookworm
ENV GOTOOLCHAIN=local

RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-venv ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install from requirements.txt rather than a hand-written pip list. The two drifted once:
# the list here omitted `mcp`, so the image could run the proxy and not the MCP server.
COPY requirements.txt /app/
RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir -r /app/requirements.txt
ENV PATH="/opt/venv/bin:${PATH}"

# Top-level modules AND the package directories. This used to be `COPY *.py *.txt *.yaml`,
# a flat glob that silently excluded every directory -- so the image shipped without the
# pack system, the lane detectors and the project profiles, and nothing failed at build
# time. A COPY that cannot fail is a COPY that cannot tell you it is incomplete.
COPY *.py *.txt *.yaml /app/
COPY packlib/ /app/packlib/
COPY packs/ /app/packs/
COPY projects/ /app/projects/
COPY orgs/ /app/orgs/
COPY oracles/ /app/oracles/

# Fail the BUILD if the pack system is not fully present and self-consistent, so a broken
# image is never published. This is the control the flat COPY was missing.
RUN /opt/venv/bin/python -m packlib.packtest \
 && /opt/venv/bin/python -m packlib.selftest_packs \
 && /opt/venv/bin/python /app/packlib/mcp_server.py --selftest

EXPOSE 8090
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -sf http://127.0.0.1:8090/v1/models || exit 1
CMD ["python3", "secure_proxy.py", "--port", "8090"]
