# ⚔️ KIDON (כידון)
> **Agentic Cyber Defense Platform** // Unit 8200-inspired Architecture

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Kidon: Active](https://img.shields.io/badge/Status-Operational-00f3ff)](https://github.com/uddeshya-23/-kidon-security)
[![OWASP: Top 10](https://img.shields.io/badge/OWASP%20Agentic-Covered-ff003c)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

**Kidon** (Hebrew for "Javelin") is a comprehensive security platform designed to secure Autonomous AI Agents. It operates on the **Titan Framework**, classifying agents by risk and applying layers of defense accordingly.

![Kidon Security Report](assets/report_screenshot.png)

---

## 🛡️ The Titan Defense Architecture

| Module | Code Name | Function | Tech Stack |
| :--- | :--- | :--- | :--- |
| **Scanner** | *The Sentry* | Static Analysis of credentials & config | Go, Regex |
| **Guard** | *The Shomer* | Runtime eBPF Kernel Watchdog | C, eBPF, Docker |
| **Strike** | *The Kidon* | Offensive Red Teaming Engine | Go, Ollama |

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
*Requires Docker*
```bash
docker build -f deploy/Dockerfile.kidon -t kidon .
docker run --privileged --pid=host kidon
```

**Offensive Strike (Red Team)**
```bash
# Attack a local agent endpoint
./kidon strike --target http://localhost:8000/chat --ai
```

**Generate Mission Report**
```bash
./kidon report
# → Opens mission_report.html in browser
```

---

## 📊 Titan Classifications

| Class | Name | Risk Level | Example |
|-------|------|------------|---------|
| **1** | Cart Titan | Low | Chatbots, RAG |
| **2** | Armored Titan | Medium | Tool-using Agents |
| **3** | Colossal Titan | Critical | Autonomous Admin Agents |

---

## 🎯 OWASP Coverage

| Threat ID | Name | Module |
|-----------|------|--------|
| ASI-01 | Goal Hijacking | Strike |
| ASI-02 | Tool Misuse | Guard |
| ASI-03 | Privilege Abuse | Scan |
| ASI-05 | Unexpected Code Exec | Guard |
| ASI-07 | Insecure Communications | Scan |

---

## 📁 Project Structure

```
kidon-security/
├── cmd/kidon/main.go         # CLI entry point
├── internal/
│   ├── static/               # Credential scanner
│   ├── runtime/              # eBPF loader
│   ├── offensive/            # Red team engine
│   └── report/               # HTML generator
├── bpf/                      # eBPF C kernels
├── deploy/                   # Docker files
└── configs/                  # Policy configuration
```

---

## 🔧 Development

```bash
# Run tests
go test ./...

# Generate eBPF artifacts (Linux only)
go generate ./internal/runtime/...

# Build Docker image
docker build -f deploy/Dockerfile.kidon -t kidon-security .
```

---

## 📝 License

MIT License - See [LICENSE](LICENSE) for details.

---

*Built for the Age of Agentic AI.*
