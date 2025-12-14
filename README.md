# ⚔️ KIDON (כידון)
> **Agentic Cyber Defense Platform** // Powered by Cilium eBPF

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Status: Operational](https://img.shields.io/badge/Status-v0.1.0-00f3ff)](https://github.com/uddeshya-23/-kidon-security)
[![Tech: Cilium eBPF](https://img.shields.io/badge/Powered%20By-Cilium%20eBPF-F6C702)](https://ebpf.io)
[![OWASP: Top 10](https://img.shields.io/badge/OWASP%20Agentic-Covered-ff003c)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

**Kidon** (Hebrew for "Javelin") is the first open-source security platform designed to bind the "Titans"—Autonomous AI Agents. It moves beyond static analysis to provide **Runtime Kernel Protection** using the same eBPF technology that powers the world's largest Kubernetes clusters.

![Kidon Security Report](assets/report_screenshot.png)

---

## 🛡️ The Titan Defense Architecture

Kidon employs a **Defense-in-Depth** strategy mapped to the **OWASP Top 10 for Agentic AI (2025)**.

| Module | Code Name | Function | Tech Stack | OWASP Coverage |
| :--- | :--- | :--- | :--- | :--- |
| **Scanner** | *The Sentry* | Static Analysis of Code & Config | Go, Regex, AST | ASI-03, ASI-04, ASI-07 |
| **Guard** | *The Shomer* | Runtime Kernel Watchdog | **Cilium eBPF**, C, Docker | ASI-02, ASI-05, ASI-10 |
| **Strike** | *The Kidon* | Offensive Red Teaming Engine | Go, Ollama (Local SLM) | ASI-01, ASI-06, ASI-08 |

---

## 🚀 Quick Start

### 1. Installation

```bash
# Clone the repo
git clone https://github.com/uddeshya-23/-kidon-security
cd kidon-security

# Build the binary
go build -o kidon cmd/kidon/main.go
```

### 2. Operational Usage

**Reconnaissance (Static Scan)**
```bash
./kidon scan ./my-agent-repo
```

**Active Defense (Runtime Guard)**  
*Requires Docker (Linux/WSL2)*. Uses eBPF to hook `sys_enter_execve`.
```bash
docker build -f deploy/Dockerfile.kidon -t kidon .
docker run --privileged --pid=host kidon
```

**Offensive Strike (Red Team)**  
Uses local Sovereign AI to generate adversarial prompts.
```bash
# Attack a local agent endpoint
./kidon strike --target http://localhost:8000/chat --ai
```

**Mission Intelligence**
```bash
./kidon report
# → Opens classified mission_report.html
```

---

## 🐝 Powered by Cilium eBPF

Kidon leverages the **`cilium/ebpf`** library to interface directly with the Linux Kernel.

* **Why?** Agents are dynamic. They generate code on the fly. Traditional firewalls cannot see what an agent "thinks."
* **How?** We attach non-intrusive probes to the kernel's syscall interface.
  * **Tracepoints:** To detect process execution (`execve`).
  * **Socket Filter (Coming v0.2):** To prevent unauthorized data exfiltration.

---

## 🔧 Development & Roadmap

**Current Version:** v0.1.0 (MVP)  
**Next Milestone:** v0.2.0 (Network Fortress)

- [x] **Phase 1:** Static Credential Scanner
- [x] **Phase 2:** Runtime Process Guard (eBPF)
- [x] **Phase 3:** Red Teaming Engine (Ollama)
- [ ] **Phase 4:** Network Egress Filtering (Cilium/eBPF) `<- NEXT`
- [ ] **Phase 5:** Kubernetes Operator

---

## 📝 License

MIT License - See [LICENSE](LICENSE) for details.

---

*Built for the Age of Agentic AI.*
