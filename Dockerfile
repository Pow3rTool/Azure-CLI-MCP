# Self-contained image for azobo (azure-cli-mcp). Build from the repo root:
#   podman build -t azobo .
# ONE image, run as TWO containers (broker + server) sharing a /run/azobo socket:
#   broker:  python obo_broker.py   (holds the OBO cert; mint tokens over the socket)
#   server:  python server.py       (default CMD; shells out to `az`, no cert access)
#
# CERT-ISOLATION IS OPERATOR-ENFORCED HERE, NOT STRUCTURAL. Unlike the systemd
# deploy (distinct broker/server users + InaccessiblePaths on the key), this image
# builds ONE uid (10001) for both roles. You MUST therefore, at run time:
#   - run broker and server as SEPARATE containers, and
#   - mount the OBO key (AZOBO_CERT_KEY/PUB) ONLY into the broker container.
# Mounting the key into the server/`az` container, or running both roles in one
# container, hands the user-driven `az` child the shared confidential-client cert and
# defeats the broker boundary. No key ships in the image; this is a run-time footgun.
# NOTE: bundles the full azure-cli (via requirements.txt) — large image, slow build; inherent
# to how azobo works (it subprocess-runs `az`). In-container the server calls the container's
# python + wrapper: run it with AZOBO_PYTHON=/usr/local/bin/python AZOBO_WRAPPER=/app/azobo.
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Pre-baked az CLI extensions — pinned + reviewed like any other dependency, NEVER
# installed at runtime (server.py hardcodes AZURE_CORE_DISABLE_DYNAMIC_INSTALL=yes
# on every az_run subprocess, by design). Fixed path so server.py's AZURE_EXTENSION_DIR
# (env-overridable via AZOBO_EXTENSION_DIR) can find it regardless of the per-call
# ephemeral AZURE_CONFIG_DIR.
ENV AZURE_EXTENSION_DIR=/opt/az-extensions
RUN az extension add --name resource-graph --version 2.1.1 \
 && chmod -R a+rX /opt/az-extensions

# server + broker + the `azobo` az-wrapper the server spawns
COPY server.py obo_broker.py azobo ./
RUN useradd --system --uid 10001 mcp
USER mcp

VOLUME ["/run/azobo"]
EXPOSE 8782
CMD ["python", "server.py"]
