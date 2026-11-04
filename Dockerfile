# ==============================================================================
# MULTI-STAGE HARDENED PRODUCTION DOCKERFILE - SECRET LEAK GUARD
# ==============================================================================
# Security Standard:
# 1. Pinned Base Image (python:3.11.9-slim-bookworm) - Avoid 'latest' drift
# 2. Multi-Stage Build: Separates compiler toolchains from lightweight runtime
# 3. Non-Root Execution: Runs under dedicated user 'appuser' (UID 10001)
# 4. Built-in Container Healthcheck Probe
# 5. Zero Secret Directives: No ENV secrets, .dockerignore excludes .env & git
# ==============================================================================

# --- Stage 1: Build & Dependency Resolution Stage ---
FROM python:3.11.9-slim-bookworm AS builder

WORKDIR /build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential gcc && \
    rm -rf /var/lib/apt/lists/*

COPY app/requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt


# --- Stage 2: Hardened Runtime Container Stage ---
FROM python:3.11.9-slim-bookworm AS runner

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/home/appuser/.local/bin:$PATH \
    PORT=5000

# Create unprivileged application user & group
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /bin/bash -m appuser

WORKDIR /app

# Copy only installed python dependencies from builder stage
COPY --from=builder /root/.local /home/appuser/.local

# Copy application code (.dockerignore guarantees .env and secrets are excluded)
COPY app/ /app/app/

# Enforce secure ownership and permissions
RUN chown -R appuser:appgroup /app /home/appuser

# Switch to non-root execution
USER appuser

EXPOSE 5000

# Container healthcheck probe
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')" || exit 1

# Production WSGI server
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "30", "app.main:app"]
