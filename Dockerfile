# syntax=docker/dockerfile:1
# -----------------------------------------------------------------------------
# Titanium Repo Operator - Production Container
# Multi-stage build with uv for deterministic, minimal runtime
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# STAGE 1: Builder - compile dependencies with uv
# -----------------------------------------------------------------------------
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder

WORKDIR /app

ENV UV_COMPILE_BYTECODE=1
ENV UV_LINK_MODE=copy

# Install dependencies first (cache layer)
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project --no-dev

# Copy source and complete install
COPY . .
RUN uv sync --frozen --no-dev

# -----------------------------------------------------------------------------
# STAGE 2: Runner - minimal production image
# -----------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS runner

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    ripgrep \
    tini \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user with explicit UID/GID
RUN groupadd -g 1000 titanium && \
    useradd -m -u 1000 -g titanium -s /bin/bash titanium

WORKDIR /app

# Copy built application from builder stage
COPY --from=builder --chown=titanium:titanium /app /app

# Set up PATH and environment
ENV PATH="/app/.venv/bin:$PATH"
ENV REPO_ROOT=/workspace
ENV PYTHONUNBUFFERED=1

# Switch to non-root user
USER titanium

# Configure git for agent operations
RUN git config --global user.name "Titanium Agent" && \
    git config --global user.email "bot@titanium.internal" && \
    git config --global --add safe.directory /workspace

# Use tini as init process for proper signal handling
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "server.py"]
