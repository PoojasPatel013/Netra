# Netra Vortex: The "Fix-It" Edition Roadmap

## 1. Project Status: Pivot to Robustness
We are shifting focus from feature expansion to **System Robustness**. We will fix the blocking architectural issues (DB Locks, GIL Latency) using a **Polyglot Architecture**.

## 2. Strategic Roadmap (The Sprints)

### Sprint 1: The Foundation (Infrastructure) 🛑
**Mandatory Pre-requisite.**
*   **Problem**: SQLite cannot handle concurrent writes from "Distributed Scanners" (Go/C++).
*   **Solution**: Replace SQLite with **PostgreSQL**.
*   **Result**: Enables true concurrency for Phase 2 & 3.

### Sprint 2: The Turbo Scout (Go) 🐹
**Focus**: Concurrency & Modern Web Scanning.
*   **Problem**: `requests` cannot scan SPA (React/Vue) sites. Python is too slow for 1000+ threads.
*   **Solution**: Build a **Go** binary with `chromedp` (Headless Chrome).
*   **Capability**: "Distributed Scanning" - Python delegates scanning to Go binaries.

### Sprint 3: The Non-Blocking Brain (Rust) 🦀
**Focus**: Performance & Memory Safety.
*   **Problem**: Heavy NLP/Regex checks freeze the API (GIL Lock).
*   **Solution**: Port "Zombie API" logic to **Rust** (via PyO3).
*   **Result**: Rust runs outside the GIL, allowing the API to stay responsive during heavy analysis.

### Sprint 4: The Ghost (C++) 🦖
**Focus**: Low-Level Systems & Red Teaming.
*   **Problem**: Need advanced adversary emulation that evades simple detection.
*   **Solution**: Build a minimal **C++** agent (`agent.exe`).
*   **Capability**: Native Windows API calls for system introspection.

### Data Science Layer (Python) 🐍
**Focus**: Pure Intelligence.
*   **Module**: `ml_engine.py` using `scikit-learn`.
*   **Role**: Remains in Python. Clustering alerts and finding critical graph nodes.

---

> **"Robustness First. Features Second."**
