# Implementation Plan - Sprint 3: The Guard (Rust) 🦀

## Goal
Implement **LogCruncher**, a blazingly fast log analysis component using **Rust**.
It will parse server logs (Apache/Nginx) to detect attack patterns (SQLi, XSS, Path Traversal) with memory safety and speed that Python cannot match for large files.

## User Review Required
> [!NOTE]
> **Performance**: Rust is chosen here because regular expression matching on GB-sized log files is CPU-intensive. Rust's `regex` crate is O(n), guaranteeing linear time execution.

## Proposed Changes

### 1. New Rust Crate (`guard/`)
#### [NEW] [guard/Cargo.toml](file:////wsl.localhost/Ubuntu-22.04/home/fierypooja/Vortex/guard/Cargo.toml)
- **Dependencies**:
    - `regex`: For pattern matching.
    - `serde`, `serde_json`: For JSON output.
    - `clap`: For CLI argument parsing.

#### [NEW] [guard/src/main.rs](file:////wsl.localhost/Ubuntu-22.04/home/fierypooja/Vortex/guard/src/main.rs)
- **Logic**:
    - Read log lines from stdin or file.
    - Apply regex signatures (e.g., `(UNION SELECT|OR 1=1)`).
    - Output detected threats as JSON.

### 2. Python Integration (The Bridge)
#### [NEW] [netra/core/modules/rust_bridge.py](file:////wsl.localhost/Ubuntu-22.04/home/fierypooja/Vortex/netra/core/modules/rust_bridge.py)
- **Class**: `LogScanner`
- **Method**: `analyze_log(filepath)`
    - Spawns `./guard_bin` subprocess.
    - Pipes log content to it.
    - Returns findings.

### 3. Infrastructure
#### [MODIFY] [netra/api.Dockerfile](file:////wsl.localhost/Ubuntu-22.04/home/fierypooja/Vortex/netra/api.Dockerfile)
- **Build Stage**: Add `FROM rust:1.75 AS rust-builder`. Compile `guard/`.
- **Runtime Stage**:
    - `COPY --from=rust-builder /app/target/release/guard /app/bin/guard_bin`

## Verification Plan
1.  **Unit Test**: Create a sample `access.log` with a known SQL injection attack.
2.  **Manual Run**: `cat sample.log | ./guard_bin` and verify JSON alert.
3.  **UI**: Upload a log file (if UI supports it) or trigger a dummy log scan.
