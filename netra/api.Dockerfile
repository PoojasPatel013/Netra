# api/Dockerfile
FROM python:3.14-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y gcc curl && rm -rf /var/lib/apt/lists/*

# Copy poetry config
COPY pyproject.toml poetry.lock ./

# Install Poetry
RUN pip install poetry && poetry config virtualenvs.create false

# Install dependencies (latest Poetry uses --without dev)
RUN poetry install --without dev

# Copy source code
COPY netra ./netra

# Expose API port
EXPOSE 8000

# Start the API
CMD ["python", "-m", "netra.main"]
