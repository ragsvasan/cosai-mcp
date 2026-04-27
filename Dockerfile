FROM python:3.12-slim

# Minimal base — no shell utilities that could be used post-compromise
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install only runtime deps (no dev extras)
COPY pyproject.toml README.md ./
COPY cosai_mcp/ ./cosai_mcp/
COPY catalog/ ./catalog/

RUN pip install --no-cache-dir -e "."

# Non-root user — scanner never needs root
RUN useradd -r -s /bin/false cosai
USER cosai

# Default entrypoint — `docker run cosai-mcp <target>` works without extra args
ENTRYPOINT ["cosai"]
CMD ["--help"]
