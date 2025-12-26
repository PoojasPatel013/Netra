FROM python:3.10-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    build-essential \
    curl \
    ruby-full \
    && rm -rf /var/lib/apt/lists/*


COPY pyproject.toml ./

RUN pip install poetry \
    && poetry config virtualenvs.create false \
    && poetry install --only main --no-root \
    && pip install "bcrypt==4.0.1" passlib[bcrypt] python-jose python-multipart minio scikit-learn pandas numpy neo4j


COPY netra ./netra
COPY run.py .

CMD ["python", "run.py", "api"]

