# Code-VulnScan Skill

A deep, flow-aware vulnerability scanning skill for AI coding assistants. Finds real, exploitable vulnerabilities — not just keyword matches.

[![Supported IDEs](https://img.shields.io/badge/IDEs-Claude%20%7C%20Codex%20%7C%20Cursor%20%7C%20Windsurf%20%7C%20Continue%20%7C%20Antigravity-blue)]()

## What it does

- **Taint-flow analysis** — traces user input from sources to dangerous sinks across function boundaries
- **Input validation review** — checks allowlists, regex anchoring, encoding bypasses, type juggling
- **Business logic analysis** — race conditions, TOCTOU, state machine bypasses, price manipulation
- **API security** — IDOR/BOLA, mass assignment, rate limiting gaps, GraphQL depth attacks
- **Auth & session review** — auth bypass, IDOR, JWT flaws, session fixation, privilege escalation
- **Cryptography review** — weak algorithms, ECB mode, insecure RNG, hardcoded keys
- **Secret detection** — entropy-based scanning + pattern matching for API keys, passwords, private keys
- **Configuration audit** — debug mode, security headers, CORS, CSP, TLS
- **IaC security** — Dockerfile, Kubernetes, Terraform, GitHub Actions misconfigurations
- **Memory safety** — buffer overflows, use-after-free, format strings (C/C++/unsafe Rust)
- **Error handling review** — stack trace leaks, enumeration oracles, sensitive data in logs
- **Dependency CVEs** — checks manifests against known-vulnerable version ranges

**False positives are eliminated** through a three-pass verification protocol: source reachability → path completeness → exploitability context.

## Supported Languages

Python, JavaScript/TypeScript, Java/Kotlin, Go, PHP, Ruby, C/C++, C#, Rust, Swift — plus infrastructure files (Dockerfile, Kubernetes YAML, Terraform HCL, GitHub Actions).

## IDE Compatibility

| IDE | Target flag | Install Path |
|-----|-------------|-------------|
| Claude Code (CLI/Desktop) | `--target claude` | `~/.claude/skills/code-vulnscan` |
| OpenAI Codex | `--target codex` | `~/.codex/skills/code-vulnscan` |
| Cursor AI | `--target cursor` | `<project>/.cursor/skills/code-vulnscan` |
| Windsurf | `--target windsurf` | `<project>/.windsurf/skills/code-vulnscan` |
| GitHub Copilot Chat | `--target copilot` | `<project>/.github/copilot-instructions.md` |
| Cline (VS Code) | `--target cline` | `<project>/.cline/skills/code-vulnscan` + `.clinerules` |
| Continue.dev | `--target continue` | `<project>/.continue/skills/code-vulnscan` |
| Antigravity | `--target antigravity` | `<project>/.agent/skills/code-vulnscan` |

## Installation

```bash
git clone https://github.com/Bhanunamikaze/Code-VulnScan-Skill.git
cd Code-VulnScan-Skill

# Claude Code (most common)
bash install.sh --target claude

# Codex
bash install.sh --target codex

# GitHub Copilot Chat (writes .github/copilot-instructions.md)
bash install.sh --target copilot --project-dir /path/to/your/project

# Cursor AI
bash install.sh --target cursor --project-dir /path/to/your/project

# Windsurf
bash install.sh --target windsurf --project-dir /path/to/your/project

# Cline (VS Code extension)
bash install.sh --target cline --project-dir /path/to/your/project

# User-wide (Claude + Codex)
bash install.sh --target global

# All project-local IDEs (Cursor, Windsurf, Copilot, Cline, Continue, Antigravity)
bash install.sh --target project --project-dir /path/to/your/project

# Every target at once
bash install.sh --target all --project-dir /path/to/your/project

# With Python deps for local scripts
bash install.sh --target claude --install-deps
```

**Safer remote install (with checksum):**
```bash
curl -fsSLO https://raw.githubusercontent.com/Bhanunamikaze/Code-VulnScan-Skill/main/install.sh
curl -fsSLO https://raw.githubusercontent.com/Bhanunamikaze/Code-VulnScan-Skill/main/install.sh.sha256
sha256sum -c install.sh.sha256
bash install.sh --target claude
```

## Usage

After installing, restart your agent session, then:

```
vulnscan scan /path/to/codebase
```

Or naturally:
```
Find security vulnerabilities in this codebase
Scan for SQL injection and XSS in this Flask app
Check for hardcoded secrets
Audit the authentication logic
Are there any vulnerable dependencies?
Give me a full security report in SARIF format
Check the Kubernetes configs for misconfigurations
Find IDOR vulnerabilities in the API
```

## Output formats

- **Markdown** — human-readable report with taint paths, code snippets, remediation
- **SARIF** — integrates with GitHub Advanced Security, VS Code Security extensions, CI/CD
- **JSON** — machine-readable for custom tooling

Reports saved to `workspace/report_<run_id>.<ext>`

## Architecture

```
Code-VulnScan-Skill/
├── SKILL.md                          # Main skill orchestration (read by agent)
├── install.sh                        # Multi-IDE installer
├── sub-skills/                       # 16 specialized analysis agents
│   ├── scan-strategy.md
│   ├── taint-analyzer.md
│   ├── input-validator.md
│   ├── business-logic-analyzer.md
│   ├── api-security-reviewer.md
│   ├── auth-reviewer.md
│   ├── crypto-reviewer.md
│   ├── secret-detector.md
│   ├── config-security-reviewer.md
│   ├── iac-security-reviewer.md
│   ├── memory-safety-analyzer.md
│   ├── error-handling-reviewer.md
│   ├── dependency-auditor.md
│   ├── vuln-classifier.md
│   ├── false-positive-filter.md
│   └── report-generator.md
├── scripts/                          # Deterministic Python helpers
│   ├── scan.py                       # Main orchestrator + SQLite state
│   ├── taint.py                      # AST-based taint analysis
│   ├── secrets.py                    # Entropy + pattern secret detection
│   ├── dependency.py                 # Dependency CVE checker
│   ├── report.py                     # Report generator (MD/JSON/SARIF)
│   └── utils/
│       ├── db.py                     # SQLite state management
│       ├── languages.py              # Language/framework detection
│       ├── files.py                  # File enumeration
│       ├── patterns.py               # Pattern matching engine
│       └── entropy.py                # Shannon entropy for secret detection
├── resources/
│   ├── patterns/                     # Per-language source/sink patterns
│   │   ├── python_patterns.json
│   │   ├── javascript_patterns.json
│   │   ├── java_patterns.json
│   │   ├── php_patterns.json
│   │   ├── go_patterns.json
│   │   └── generic_patterns.json
│   └── references/
│       ├── owasp-top10.md
│       ├── cwe-taxonomy.md
│       └── false-positive-guide.md
└── workspace/                        # Scan state, intermediate outputs, reports
```

## How findings are verified

Every candidate finding passes three mandatory verification passes before being reported:

1. **Source reachability** — Is the input genuinely user-controlled? (Not hardcoded, not trusted-only)
2. **Path completeness** — Does the tainted value actually reach the sink with no effective sanitization?
3. **Exploitability context** — Can an attacker realistically trigger this in context?

Only **Confirmed** and **Likely** findings appear in the final report.
