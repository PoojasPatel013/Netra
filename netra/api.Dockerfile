# api/Dockerfile
FROM python:3.10-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y gcc g++ build-essential curl && rm -rf /var/lib/apt/lists/*

# Copy poetry config
COPY pyproject.toml poetry.lock ./

# Install Poetry
RUN pip install poetry && poetry config virtualenvs.create false

# Fix lockfile mismatch and install
RUN poetry lock && poetry install --without dev --no-root

# Copy source code
COPY netra ./netra

# Expose API port
EXPOSE 8000

# Start the API
CMD ["python", "-m", "netra.main"]
