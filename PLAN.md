# ⚔️ Kidon: Master Development Plan
**Current Status:** v0.2.1 (Pivot to Supply Chain)

---

## 📅 Roadmap Overview

| Phase | Feature | Status | Notes |
| :--- | :--- | :--- | :--- |
| **P1** | **Static Scanner** | ✅ **DONE** | Credential detection active. |
| **P2** | **Process Guard** | ✅ **DONE** | eBPF execution blocking active. |
| **P3** | **Red Teaming** | ✅ **DONE** | Ollama-based attacks active. |
| **P4** | **Network Guard** | ⚠️ **EXPERIMENTAL** | DNS Resolver active. Blocking requires Kernel BTF fix (Deferred to v0.3). |
| **P5** | **Supply Chain** | 🚀 **IN PROGRESS** | OSV.dev integration for `requirements.txt`. |
| **P6** | **Command Cockpit**| ⏳ **PENDING** | TUI Dashboard (Bubble Tea). |

---

## 🛠️ Execution Details

### Phase 4: Network Fortress (Stabilization)
**Goal:** Keep the feature available but non-blocking to prevent crashes.
* **Action:** Mark as `[EXPERIMENTAL]` in CLI.
* **Logic:** If eBPF hook fails to load (due to BTF), log warning and fallback to "Passive DNS Mode" (Logging only).

### Phase 5: Supply Chain Intelligence (The "Viper" Module)
**Goal:** Detect vulnerable dependencies (OWASP ASI-04).
* **Task 5.1: Dependency Parser (`internal/static/parser.go`)**
    * Support: `requirements.txt` (Python), `go.mod` (Go), `package.json` (Node).
    * Logic: Regex parse to extract `name` and `version`.
* **Task 5.2: OSV Client (`internal/static/osv.go`)**
    * API: `https://api.osv.dev/v1/querybatch`.
    * Logic: Send batch request. If `vulns` found -> Create Critical Issue.
* **Task 5.3: Integration**
    * Add to `kidon scan` loop. Results appear in `mission_report.html`.

### Phase 6: The Command Cockpit (UI)
**Goal:** Unified Terminal Dashboard.
* **Tech:** `charmbracelet/bubbletea`.
* **Views:**
    1.  **Sentry:** Scan results & file tree.
    2.  **Shomer:** Live streaming logs from RingBuffer.
    3.  **Strike:** Interactive chat window.
