FROM python:3.10-slim

# Install System Dependencies (including Ruby)
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
RUN poetry install --without dev

# Install Ruby Gems (if any are needed by your scripts, e.g., json is built-in but network libs might not be)
# RUN gem install httparty ... (Add if needed later)

# Copy Application Code
COPY netra ./netra

# Run Worker
CMD ["python", "-m", "netra.core.ingestion.worker"]
