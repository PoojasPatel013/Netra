FROM python:3.10-slim

# Install System Dependencies (including Ruby for Legacy Scanners)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ruby-full \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python Deps
COPY pyproject.toml poetry.lock ./
RUN pip install poetry && poetry config virtualenvs.create false
RUN poetry install --only main --no-root

# Copy Application Code
COPY netra ./netra

# Default command (can be overridden by docker-compose)
CMD ["python", "-m", "netra.workers.ingest"]
