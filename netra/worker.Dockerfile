# Stage 1: Go Builder (TurboScan)
FROM golang:1.21 AS go-builder
WORKDIR /app
COPY scout/go.mod scout/main.go ./
RUN go mod tidy && go build -o scout_bin main.go

# Stage 2: Rust Builder (LogCruncher)
FROM rust:1.93-slim AS rust-builder
WORKDIR /app
COPY guard/ .
RUN cargo build --release

# Stage 3: Final Worker Image
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
RUN poetry lock && poetry install --without dev --no-root

# Copy Application Code
COPY netra ./netra
COPY run.py .

# Install Binaries
RUN mkdir -p /app/bin
COPY --from=go-builder /app/scout_bin /app/bin/scout_bin
COPY --from=rust-builder /app/target/release/guard /app/bin/guard_bin

# Run Worker
CMD ["python", "-m", "netra.core.ingestion.worker"]
