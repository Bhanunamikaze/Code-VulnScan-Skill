# Code-VulnScan Skill

A deep, flow-aware vulnerability scanning skill for AI coding assistants. Finds real, exploitable vulnerabilities — not just keyword matches.

[![Supported IDEs](https://img.shields.io/badge/IDEs-Claude%20%7C%20Codex%20%7C%20Cursor%20%7C%20Windsurf%20%7C%20Copilot%20%7C%20Cline%20%7C%20Continue%20%7C%20Antigravity-blue)]()
[![Languages](https://img.shields.io/badge/Languages-10%2B-green)]()
[![CVEs](https://img.shields.io/badge/CVE%20Database-100%2B-orange)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## What it does

- **Taint-flow analysis** — traces user input from sources to dangerous sinks across function boundaries (Python AST; JS/PHP variable-assignment tracking)
- **Input validation review** — checks allowlists, regex anchoring, encoding bypasses, type juggling
- **Business logic analysis** — race conditions, TOCTOU, state machine bypasses, price manipulation
- **API security** — IDOR/BOLA, mass assignment, rate limiting gaps, GraphQL depth/complexity attacks
- **Auth & session review** — auth bypass, IDOR, JWT flaws, session fixation, privilege escalation
- **Cryptography review** — weak algorithms, ECB mode, insecure RNG, hardcoded keys
- **Secret detection** — entropy-based scanning + 45+ pattern rules for API keys, passwords, private keys; optional git history scan
- **Configuration audit** — debug mode, security headers, CORS, CSP, TLS misconfigurations
- **IaC security** — Dockerfile, Kubernetes, Terraform, GitHub Actions, GitLab CI, Docker Compose
- **Memory safety** — buffer overflows, use-after-free, format strings (C/C++/unsafe Rust)
- **ReDoS detection** — catastrophic backtracking analysis: nested quantifiers, alternation prefix overlap, complexity estimation
- **GraphQL security** — introspection exposure, depth/complexity limits, batching abuse, field-level auth gaps
- **Mobile security** — Android WebView/exported components, iOS ATS/Keychain/UIWebView, deep link hijacking
- **Error handling review** — stack trace leaks, enumeration oracles, sensitive data in logs
- **Dependency CVEs** — checks 13 manifest types against 100+ known-vulnerable version ranges

**False positives are eliminated** through a three-pass verification protocol: source reachability → path completeness → exploitability context.

## Supported Languages

Python, JavaScript/TypeScript, Java/Kotlin, Go, PHP, Ruby, C/C++, C#, Rust, Swift, Bash — plus infrastructure files (Dockerfile, Kubernetes YAML, Terraform HCL, GitHub Actions, GitLab CI, Docker Compose).

## IDE Compatibility

| IDE | Target flag | Installed file |
|-----|-------------|---------------|
| Claude Code (CLI/Desktop) | `--target claude` | `~/.claude/skills/code-vulnscan/` |
| Claude Code / Cowork (project/team) | `--target cowork` | `<project>/.claude/skills/code-vulnscan/` |
| OpenAI Codex | `--target codex` | `~/.codex/skills/code-vulnscan/` |
| Cursor AI | `--target cursor` | `<project>/.cursor/rules/code-vulnscan.mdc` |
| Windsurf | `--target windsurf` | `<project>/.windsurf/rules/code-vulnscan.md` |
| GitHub Copilot Chat | `--target copilot` | `<project>/.github/copilot-instructions.md` |
| Cline (VS Code) | `--target cline` | `<project>/.clinerules` |
| Continue.dev | `--target continue` | `<project>/.continue/prompts/vulnscan.prompt` |
| Antigravity | `--target antigravity` | `<project>/.agent/skills/code-vulnscan/` |

## Installation

All `--online` commands below download the latest release package automatically.

### Quick install (no cloning required)

**Linux / macOS:**
```bash
# Default: installs to every target at once
curl -fsSL https://raw.githubusercontent.com/Bhanunamikaze/Code-VulnScan-Skill/main/install.sh | bash -s -- --online

# Claude Code only
curl -fsSL https://raw.githubusercontent.com/Bhanunamikaze/Code-VulnScan-Skill/main/install.sh | bash -s -- --online --target claude

# User-wide (Claude + Codex)
curl -fsSL https://raw.githubusercontent.com/Bhanunamikaze/Code-VulnScan-Skill/main/install.sh | bash -s -- --online --target global

# Every target, scoped to a project
curl -fsSL https://raw.githubusercontent.com/Bhanunamikaze/Code-VulnScan-Skill/main/install.sh | bash -s -- --online --target all --project-dir /path/to/your/project
```

**Windows (PowerShell):**
```powershell
# Download installer, then run with --online
irm https://raw.githubusercontent.com/Bhanunamikaze/Code-VulnScan-Skill/main/install.ps1 -OutFile install.ps1

# Default: installs to every target at once
pwsh ./install.ps1 --online

# Claude Code only
pwsh ./install.ps1 --online --target claude

# Every target, scoped to a project
pwsh ./install.ps1 --online --target all --project-dir C:\path\to\your\project
```

### From source

```bash
git clone https://github.com/Bhanunamikaze/Code-VulnScan-Skill.git
cd Code-VulnScan-Skill

# Claude Code (most common)
bash install.sh --target claude

# Codex
bash install.sh --target codex

# Claude Cowork / project-scoped (installs to .claude/skills/, commit to git to share with team)
bash install.sh --target cowork --project-dir /path/to/your/project

# GitHub Copilot Chat (writes .github/copilot-instructions.md)
bash install.sh --target copilot --project-dir /path/to/your/project

# Cursor AI (writes .cursor/rules/code-vulnscan.mdc)
bash install.sh --target cursor --project-dir /path/to/your/project

# Windsurf (writes .windsurf/rules/code-vulnscan.md)
bash install.sh --target windsurf --project-dir /path/to/your/project

# Cline VS Code extension (appends to .clinerules)
bash install.sh --target cline --project-dir /path/to/your/project

# Continue.dev (writes .continue/prompts/vulnscan.prompt)
bash install.sh --target continue --project-dir /path/to/your/project

# User-wide (Claude + Codex)
bash install.sh --target global

# All project-local IDEs at once
bash install.sh --target project --project-dir /path/to/your/project

# Every target at once
bash install.sh --target all --project-dir /path/to/your/project

# With Python deps for local scripts
bash install.sh --target claude --install-deps
```

**Windows (PowerShell) — from source:**
```powershell
# Claude Code
.\install.ps1 --target claude

# Cursor AI
.\install.ps1 --target cursor --project-dir C:\path\to\project

# All targets
.\install.ps1 --target all --project-dir C:\path\to\project
```

**Safer remote install (with checksum verification):**
```bash
curl -fsSLO https://raw.githubusercontent.com/Bhanunamikaze/Code-VulnScan-Skill/main/install.sh
curl -fsSLO https://raw.githubusercontent.com/Bhanunamikaze/Code-VulnScan-Skill/main/install.sh.sha256
sha256sum -c install.sh.sha256
bash install.sh --online
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
Give me an HTML security report
Check the Kubernetes configs for misconfigurations
Find IDOR vulnerabilities in the API
Analyze GraphQL schema for security issues
Check for ReDoS vulnerabilities in the regex patterns
Scan git history for committed secrets
Review iOS and Android code for insecure storage
```

## Output formats

- **Markdown** — human-readable report with taint paths, code snippets, remediation
- **HTML** — standalone report with dark mode, collapsible sections, severity badges, code blocks
- **SARIF** — integrates with GitHub Advanced Security, VS Code Security extensions, CI/CD
- **JSON** — machine-readable for custom tooling

Reports saved to `workspace/report_<run_id>.<ext>`

## Architecture

```
Code-VulnScan-Skill/
├── SKILL.md                          # Main skill orchestration (read by agent)
├── CONTRIBUTING.md                   # How to add patterns, sub-skills, CVEs
├── SECURITY.md                       # Responsible disclosure policy
├── install.sh                        # Multi-IDE installer (Linux/macOS)
├── install.ps1                       # Multi-IDE installer (Windows/PowerShell)
├── sub-skills/                       # 19 specialized analysis agents
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
│   ├── report-generator.md
│   ├── regex-analyzer.md             # ReDoS / catastrophic backtracking
│   ├── graphql-security-reviewer.md  # GraphQL-specific attack surface
│   └── mobile-security-reviewer.md  # iOS / Android security
├── scripts/                          # Deterministic Python helpers
│   ├── scan.py                       # Main orchestrator + SQLite state + IaC pass
│   ├── taint.py                      # AST taint (Python) + variable tracking (JS/PHP)
│   ├── secrets.py                    # Entropy + 45+ pattern rules + git history scan
│   ├── dependency.py                 # Dependency CVE checker (100+ CVEs, 13 manifest types)
│   ├── report.py                     # Report generator (MD/HTML/JSON/SARIF)
│   ├── regex_analyzer.py             # ReDoS complexity estimator
│   └── utils/
│       ├── db.py                     # SQLite state management
│       ├── languages.py              # Language/framework detection
│       ├── files.py                  # File enumeration
│       ├── patterns.py               # Pattern matching engine
│       └── entropy.py                # Shannon entropy for secret detection
├── resources/
│   ├── patterns/                     # Per-language source/sink patterns (11 files)
│   │   ├── python_patterns.json
│   │   ├── javascript_patterns.json
│   │   ├── java_patterns.json
│   │   ├── php_patterns.json
│   │   ├── go_patterns.json
│   │   ├── ruby_patterns.json
│   │   ├── csharp_patterns.json
│   │   ├── c_patterns.json
│   │   ├── rust_patterns.json
│   │   ├── kotlin_patterns.json
│   │   ├── swift_patterns.json
│   │   ├── bash_patterns.json
│   │   ├── yaml_patterns.json
│   │   └── generic_patterns.json
│   └── references/
│       ├── owasp-top10.md
│       ├── cwe-taxonomy.md           # 29 CWE entries with CVSS ranges and OWASP mapping
│       └── false-positive-guide.md
├── tests/
│   ├── test_scripts.py               # Unit tests (pytest)
│   └── fixtures/                     # Intentionally vulnerable code samples
│       ├── vuln_python.py
│       ├── vuln_javascript.js
│       └── vuln_go.go
└── workspace/                        # Scan state, intermediate outputs, reports
```

## How findings are verified

Every candidate finding passes three mandatory verification passes before being reported:

1. **Source reachability** — Is the input genuinely user-controlled? (Not hardcoded, not trusted-only)
2. **Path completeness** — Does the tainted value actually reach the sink with no effective sanitization?
3. **Exploitability context** — Can an attacker realistically trigger this in context?

Only **Confirmed** and **Likely** findings appear in the final report.

## Running the scripts locally

```bash
pip install -r requirements.txt

# Scan a codebase for secrets
python3 scripts/secrets.py --path /path/to/repo --pretty

# Scan git history for committed secrets
python3 scripts/secrets.py --path /path/to/repo --git-history --max-commits 500

# Check dependencies for CVEs
python3 scripts/dependency.py --path /path/to/repo --pretty

# Detect ReDoS in a codebase
python3 scripts/regex_analyzer.py --path /path/to/repo --pretty

# Run all tests
python3 -m pytest tests/ -v
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add language patterns, sub-skills, CVEs, and IDE install targets.

## Security

See [SECURITY.md](SECURITY.md) for the responsible disclosure policy.
