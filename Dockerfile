FROM python:3.10-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    curl \
    ruby-full \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy poetry config (ignore local lockfile to force regeneration)
COPY pyproject.toml ./

# Install Poetry
RUN pip install poetry && poetry config virtualenvs.create false

# Generate fresh lockfile and install dependencies
RUN poetry lock && poetry install --without dev --no-root

# Copy application code
COPY netra ./netra
COPY run.py .

CMD ["python", "run.py", "api"]

