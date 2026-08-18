# syntax=docker/dockerfile:1
#
# Hardened image for the Agentic SOC application.
#
# Security choices:
#   * multi-stage build -- build tooling never ships in the runtime image;
#   * non-root user with no shell and no home write access outside /app/state;
#   * no compilers, curl, or package managers in the final layer;
#   * PYTHONDONTWRITEBYTECODE keeps the application tree clean so it can be
#     mounted read-only at runtime (see docker-compose.yml).

# ---------------------------------------------------------------------------
# Stage 1: build dependencies into a virtualenv
# ---------------------------------------------------------------------------
FROM python:3.11-slim-bookworm AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# build-essential is needed by a few wheels; it stays in this stage only.
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install from the hash-pinned lockfile, not the ranged manifest. --require-hashes
# makes the build reproducible and refuses any artifact whose content does not
# match what was reviewed: a compromised or re-uploaded package version fails the
# install rather than shipping. requirements.txt remains the human-edited input;
# regenerate the lock with:
#     pip-compile --generate-hashes --output-file=requirements.lock requirements.txt
COPY requirements.lock .
RUN pip install --upgrade pip \
 && pip install --require-hashes --no-deps -r requirements.lock

# ---------------------------------------------------------------------------
# Stage 2: runtime
# ---------------------------------------------------------------------------
FROM python:3.11-slim-bookworm AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    ANONYMIZED_TELEMETRY=False \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false

# Unprivileged runtime user. --no-create-home plus an explicit state directory
# means the only writable path is the one we grant on purpose.
RUN groupadd --system --gid 10001 soc \
 && useradd --system --uid 10001 --gid soc --no-create-home --shell /usr/sbin/nologin soc

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
COPY --chown=root:root src/ ./src/
COPY --chown=root:root data/ ./data/
COPY --chown=root:root pyproject.toml ./

# The single writable location: checkpoints, audit log and vector index.
RUN mkdir -p /app/state && chown -R soc:soc /app/state

USER soc
EXPOSE 8501

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8501/_stcore/health', timeout=3).status==200 else 1)"

CMD ["streamlit", "run", "src/ui/app.py", \
     "--server.address=0.0.0.0", \
     "--server.port=8501", \
     "--server.headless=true", \
     "--browser.gatherUsageStats=false"]
