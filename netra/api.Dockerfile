# Stage 1: Go Builder (TurboScan)
FROM golang:1.21 AS go-builder
WORKDIR /app
COPY scout/go.mod scout/main.go ./
# If go.sum exists, copy it too. For now ignore.
RUN go mod tidy && go build -o scout_bin main.go

# Stage 2: Rust Builder (LogCruncher)
FROM rust:1.93-slim AS rust-builder
WORKDIR /app
COPY guard/ .
RUN cargo build --release

# Stage 3: Final Image (Python)
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
COPY run.py .
# Move binary to /app/bin to survive volume mount overlay
RUN mkdir -p /app/bin
COPY --from=go-builder /app/scout_bin /app/bin/scout_bin
COPY --from=rust-builder /app/target/release/guard /app/bin/guard_bin

# Expose API port
EXPOSE 8000

# Start the API
CMD ["python", "run.py", "serve"]
