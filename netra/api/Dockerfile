# Stage 1: Runtime API (Python only)
FROM python:3.10-slim

WORKDIR /app

RUN apt-get update && apt-get install -y gcc g++ curl && rm -rf /var/lib/apt/lists/*
COPY pyproject.toml poetry.lock ./
RUN pip install poetry && poetry config virtualenvs.create false
RUN poetry install --only main --no-root

COPY netra ./netra

# Run the API
CMD ["uvicorn", "netra.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
