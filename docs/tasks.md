# Code-VulnScan Skill — Task Tracker

Status legend: `[ ]` pending · `[~]` in progress · `[x]` done

---

## Setup & IDE Support

- [x] `install.sh` supports claude, codex, antigravity, cursor, windsurf, continue, copilot, cline, global, project, all
- [x] `install.ps1` (PowerShell/Windows) — mirrors install.sh, all targets
- [x] Each IDE target installs in that IDE's native format:
  - claude/codex/antigravity → `skills/` directory (native SKILL.md support)
  - cursor → `.cursor/rules/code-vulnscan.mdc` (Cursor MDC format)
  - windsurf → `.windsurf/rules/code-vulnscan.md` (Windsurf rules directory)
  - copilot → `.github/copilot-instructions.md`
  - cline → `.clinerules` (with block markers for idempotent updates)
  - continue → `.continue/prompts/vulnscan.prompt` (slash command format)
- [x] `--online` mode (curl/Invoke-WebRequest latest release archive)
- [x] `install.sh.sha256` checksum file
- [ ] **Zed editor target** (`--target zed`) — `.zed/settings.json` AI context
- [ ] **Aider target** (`--target aider`) — `.aider.conf.yml` convention file
- [ ] **Windows SHA-256** — `install.ps1.sha256` for PowerShell verification

---

## Language Pattern Files (resources/patterns/)

| File | Status | Notes |
|------|--------|-------|
| `python_patterns.json` | [x] Done | SQLi, CMDi, path traversal, XSS/SSTI, SSRF, deserialization, crypto, auth |
| `javascript_patterns.json` | [x] Done | XSS, SQLi, CMDi, path traversal, SSRF, prototype pollution, crypto |
| `java_patterns.json` | [x] Done | SQLi, CMDi, XXE, deserialization, path traversal, crypto |
| `php_patterns.json` | [x] Done | SQLi, CMDi, path traversal, XSS, deserialization, crypto |
| `go_patterns.json` | [x] Done | SQLi, CMDi, path traversal, SSRF, crypto, XSS |
| `generic_patterns.json` | [x] Done | Secrets, debug mode, TLS bypass, IaC |
| `ruby_patterns.json` | [x] Done | Rails SQLi, CMDi (backtick/system/exec), XSS (html_safe/raw), path traversal, mass assignment, deserialization, crypto, SSRF — 8 categories, 45 patterns |
| `csharp_patterns.json` | [x] Done | SQLi, CMDi (Process.Start), path traversal, XXE, deserialization (BinaryFormatter/TypeNameHandling), crypto, SSRF, open redirect — 8 categories, 41 patterns |
| `c_patterns.json` | [x] Done | Buffer overflow (gets/strcpy/sprintf/scanf %s), format string, integer overflow in alloc, use-after-free, null pointer, TOCTOU, dangerous functions — 7 categories, 35 patterns |
| `rust_patterns.json` | [x] Done | unsafe blocks, raw pointer deref, slice::from_raw_parts, mem::transmute, FFI, panic/unwrap, integer truncation, SQL injection, path traversal — 7 categories, 31 patterns |
| `kotlin_patterns.json` | [x] Done | SQLi (string templates), CMDi, path traversal, deserialization, crypto, Android-specific (WebView/MODE_WORLD/LogCat), SSRF — 7 categories, 33 patterns |
| `swift_patterns.json` | [x] Done | SQLite exec, CMDi (Process/NSTask), path traversal, Keychain misuse, ATS bypass, CommonCrypto weak algos, WebView, deep link — 8 categories, 26 patterns |
| `bash_patterns.json` | [x] Done | eval injection, unquoted expansion, PATH injection, curl-pipe-bash RCE, info disclosure (set -x), temp file TOCTOU, hardcoded secrets — 7 categories, 30 patterns |
| `yaml_patterns.json` | [ ] **Missing** | Expanded K8s, Helm, GitHub Actions, GitLab CI, Docker Compose patterns beyond generic |

---

## Script Completeness (scripts/)

### scan.py
- [x] File enumeration + SQLite state management
- [x] Pattern-match sweep across all language files
- [x] `--status-only`, `--update-findings` commands
- [x] **`--resume` flag** — skips already-scanned files using SQLite state
- [x] **IaC-specific pass** — `enumerate_iac_files()` dedicated enumeration for Dockerfile, `*.tf`, GitHub Actions, GitLab CI, Docker Compose, K8s manifests
- [x] **`--min-severity` flag** — accepted in argparse (severity filtering in report.py)
- [ ] Severity-based filtering applied at sweep time (currently filtering happens at report stage)

### taint.py
- [x] Python AST-based taint analysis (proper source/sink/variable tracking within functions)
- [x] JS/PHP/Go proximity-based pattern matching (working but limited)
- [ ] **JavaScript AST taint** — regex-based AST walk or call tree via grep-based interprocedural tracing
- [ ] **PHP taint** — improve from proximity to variable assignment tracking
- [ ] **Go taint** — improve from proximity to variable assignment tracking
- [ ] **Cross-file interprocedural taint** — follow tainted variable into functions defined in other files

### secrets.py
- [x] Shannon entropy scoring
- [x] 25+ named credential patterns (AWS, GitHub, Stripe, Slack, OpenAI, etc.)
- [x] False positive filtering
- [ ] **Add more patterns**: Azure keys, GCP service account JSON, Twilio auth tokens, Heroku API keys, npm tokens, Docker Hub tokens, Vault tokens, Databricks tokens
- [ ] **Git history scanning** — `--git-history` flag scanning `git log -p` diff output

### dependency.py
- [x] Python (requirements.txt, Pipfile, pyproject.toml), JavaScript (package.json), Java (pom.xml), Go (go.mod), Ruby (Gemfile.lock), PHP (composer.json)
- [x] **`Cargo.toml`** — Rust dependency parsing + RustSec CVEs
- [x] **`.csproj` / `packages.config`** — C#/.NET NuGet dependency parsing
- [x] **`build.gradle` / `build.gradle.kts`** — Gradle dependency block parsing (Groovy + Kotlin DSL)
- [x] **`pyproject.toml`** — PEP 517/518 + Poetry dependency parsing
- [ ] **CVE database expansion** — current list is ~60, should be 200+

### report.py
- [x] Markdown, JSON, SARIF v2.1.0 output
- [x] Severity grouping, taint path display, remediation checklist
- [ ] **HTML report format** — standalone HTML with syntax highlighting
- [ ] **CSV export** — for importing into Jira, Linear, GitHub Issues
- [ ] **GitHub Issues creation** — optional `--create-issues` flag using `gh` CLI

### regex_analyzer.py
- [x] **New script** — ReDoS detection: nested quantifier analysis, alternation common-prefix detection, complexity estimation (catastrophic/exponential/polynomial/linear), severity classification, remediation guidance

---

## Sub-Skills (sub-skills/)

| File | Status |
|------|--------|
| `scan-strategy.md` | [x] Done |
| `taint-analyzer.md` | [x] Done |
| `input-validator.md` | [x] Done |
| `business-logic-analyzer.md` | [x] Done |
| `api-security-reviewer.md` | [x] Done |
| `auth-reviewer.md` | [x] Done |
| `crypto-reviewer.md` | [x] Done |
| `secret-detector.md` | [x] Done |
| `config-security-reviewer.md` | [x] Done |
| `iac-security-reviewer.md` | [x] Done |
| `memory-safety-analyzer.md` | [x] Done |
| `error-handling-reviewer.md` | [x] Done |
| `dependency-auditor.md` | [x] Done |
| `vuln-classifier.md` | [x] Done |
| `false-positive-filter.md` | [x] Done |
| `report-generator.md` | [x] Done |
| `regex-analyzer.md` | [ ] **Missing** — ReDoS detection, catastrophic backtracking, complexity estimation |
| `graphql-security-reviewer.md` | [ ] **Missing** — Dedicated GraphQL sub-skill: introspection, depth/complexity, batching, field-level auth |
| `mobile-security-reviewer.md` | [ ] **Missing** — iOS/Android: insecure storage, WebView XSS, cert pinning bypass, deep link hijacking |

---

## Resource Files (resources/)

| File | Status |
|------|--------|
| `resources/references/owasp-top10.md` | [x] Done |
| `resources/references/false-positive-guide.md` | [x] Done |
| `resources/references/cwe-taxonomy.md` | [ ] **Missing** — CWE quick-reference table for common vulnerability types |
| `resources/report-templates/sarif_schema.json` | [ ] **Missing** — SARIF schema stub for validation |

---

## Tests (tests/)

- [ ] **`tests/test_scripts.py`** — unit tests for scan.py, taint.py, secrets.py, dependency.py, report.py
- [ ] **`tests/fixtures/`** — small intentionally-vulnerable code samples in each language
- [ ] **CI workflow** — `.github/workflows/ci.yml` that runs tests on push

---

## Documentation

- [ ] **`CONTRIBUTING.md`** — how to add new language patterns, sub-skills, CVEs
- [ ] **`SECURITY.md`** — responsible disclosure policy
- [ ] **`docs/architecture.md`** — architecture diagram and workflow explanation
- [ ] **Update `README.md`** — add all IDE targets to compatibility table

---

## Priority Order

### P0 — DONE ✓
1. ~~`ruby_patterns.json`~~ — done
2. ~~`csharp_patterns.json`~~ — done
3. ~~`c_patterns.json`~~ — done
4. ~~`rust_patterns.json`~~ — done
5. ~~`kotlin_patterns.json`~~ — done
6. ~~`swift_patterns.json`~~ — done
7. ~~`bash_patterns.json`~~ — done
8. ~~`dependency.py` Cargo.toml/.csproj/build.gradle parsing~~ — done
9. ~~`scan.py` IaC pass + `--resume` flag~~ — done
10. ~~`regex_analyzer.py`~~ — done

### P1 — Next up
11. `regex-analyzer.md` sub-skill
12. `resources/references/cwe-taxonomy.md`
13. CVE database expansion (60 → 200+ CVEs)
14. `yaml_patterns.json` — expanded K8s/GitHub Actions/GitLab CI patterns

### P2 — Quality and depth
15. JavaScript / Go / PHP improved taint analysis in `taint.py`
16. `graphql-security-reviewer.md`
17. Git history secret scanning in `secrets.py`
18. HTML report format in `report.py`
19. `tests/` with fixtures

### P3 — Nice to have
20. `install.ps1.sha256`
21. Aider / Zed install targets
22. CSV export + GitHub Issues creation
23. `mobile-security-reviewer.md`
24. CI/CD workflow + `CONTRIBUTING.md` + `SECURITY.md`
