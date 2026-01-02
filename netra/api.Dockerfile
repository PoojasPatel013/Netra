# api/Dockerfile
FROM python:3.10-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y gcc g++ build-essential curl && rm -rf /var/lib/apt/lists/*

# Copy poetry config (ignore local lockfile)
COPY pyproject.toml ./

# Install Poetry
RUN pip install poetry && poetry config virtualenvs.create false

# Generate fresh lockfile and install dependencies
RUN poetry lock && poetry install --without dev --no-root

# Copy source code
COPY netra ./netra

# Expose API port
EXPOSE 8000

# Start the API
CMD ["python", "-m", "netra.main"]
