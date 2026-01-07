# Implementation Plan - Sprint 2: The Scout (Go) 🐹

## Goal
Implement **TurboScan**, a high-performance **Go** binary for SPA scanning.
**Architecture Update**: To prevent Docker bloat, we will use a **Decoupled Microservices** pattern. The Go binary will run in the API container but control a separate, lightweight `headless-shell` container over the network.

## User Review Required
> [!TIP]
> **Cloud Native Approach**: This "Remote Browser" pattern allows us to easily move the scanning to the cloud (AWS Lambda/Fargate) later without changing code, just an environment variable (`CHROME_URL`).

## Proposed Changes

### 1. New Go Module (`scout/`)
#### [NEW] [scout/go.mod](file:////wsl.localhost/Ubuntu-22.04/home/fierypooja/Vortex/scout/go.mod)
- Dependency: `github.com/chromedp/chromedp` (Supports remote allocators).

#### [NEW] [scout/main.go](file:////wsl.localhost/Ubuntu-22.04/home/fierypooja/Vortex/scout/main.go)
- **Logic**: Connect to `ws://chrome:9222` instead of launching a local browser.
- **CLI Flags**: `-target`, `-chrome-url` (Default: `ws://chrome:9222`).

### 2. Infrastructure (The "Sidecar")
#### [MODIFY] [docker-compose.yml](file:////wsl.localhost/Ubuntu-22.04/home/fierypooja/Vortex/docker-compose.yml)
- **Add Service**: `chrome`
    - Image: `chromedp/headless-shell:latest` (Much smaller than full Chrome)
    - Ports: `9222:9222`
- **Link**: `netra` depends on `chrome`.

#### [MODIFY] [netra/api.Dockerfile](file:////wsl.localhost/Ubuntu-22.04/home/fierypooja/Vortex/netra/api.Dockerfile)
- **Build Stage**: Compile Go binary.
- **Runtime Stage**: **NO** Chromium installation required (Saves ~500MB). Only the 10MB binary is copied.

### 3. Python Integration
#### [NEW] [netra/core/modules/go_bridge.py](file:////wsl.localhost/Ubuntu-22.04/home/fierypooja/Vortex/netra/core/modules/go_bridge.py)
- Call `./scout_bin -target X -chrome-url ws://chrome:9222`

## Verification Plan
1.  **Microservice Check**: `curl localhost:9222/json/version` to see if Headless Shell is responding.
2.  **Scan Test**: Run the Go binary and verify it captures the page title of a React app.
