# Self-contained image for azobo (azure-cli-mcp). Build from the repo root:
#   podman build -t azobo .
# ONE image, run as TWO containers (broker + server) sharing a /run/azobo socket:
#   broker:  python obo_broker.py   (holds the OBO cert; mint tokens over the socket)
#   server:  python server.py       (default CMD; shells out to `az`, no cert access)
# NOTE: bundles the full azure-cli (via requirements.txt) — large image, slow build; inherent
# to how azobo works (it subprocess-runs `az`). In-container the server calls the container's
# python + wrapper: run it with AZOBO_PYTHON=/usr/local/bin/python AZOBO_WRAPPER=/app/azobo.
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# server + broker + the `azobo` az-wrapper the server spawns
COPY server.py obo_broker.py azobo ./
RUN useradd --system --uid 10001 mcp
USER mcp

VOLUME ["/run/azobo"]
EXPOSE 8782
CMD ["python", "server.py"]
