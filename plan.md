# Code-VulnScan — Accuracy Improvement Plan

> Audience: implementing engineer (Sonnet/Opus). Status: ready to execute.
> Goal: cut false negatives by ≥40% and false positives by ≥30% on a fixed benchmark while keeping scan time under 2× current.

---

## 1. Executive Summary

The current scanner is strong on **breadth of vulnerability classes**, **report quality** (MD/HTML/JSON/SARIF), and **IaC coverage**, but has serious **depth gaps** in three areas that drive most missed/spurious findings:

1. **Taint analysis is intra-procedural and Python/JS-only** — anything that crosses a function boundary, hits a non-supported language, or flows through a container/attribute is invisible.
2. **No ORM/sanitizer awareness on the sink side** — Django `QuerySet.filter()`, SQLAlchemy parameterized queries, `bleach.clean()` arguments, etc. all generate false positives.
3. **CVE database is hardcoded, ~196 entries, no transitive dep walk, no lockfile parsing** — entire dependency trees are invisible.

These three gaps account for the largest accuracy loss. Phases 1–3 below tackle them directly. Phases 4–5 expand coverage breadth and improve agent-driven orchestration.

---

## 2. Current State

### 2.1 Strengths (preserve, don't regress)
- **Python AST taint** with framework-aware sources (Flask/Django/FastAPI). `scripts/taint.py:254-357`
- **IaC coverage**: 50+ rules across Dockerfile/K8s/Terraform/GitHub Actions/GitLab CI. `resources/patterns/yaml_patterns.json`, `generic_patterns.json`
- **Three-pass FP protocol** (source reachability → path completeness → exploitability). `sub-skills/false-positive-filter.md:14-89`
- **Multi-format reporting** with CWE/CVSS/SARIF emission. `scripts/report.py`
- **19 sub-skills** covering a wide vuln-class surface. `sub-skills/`
- **Three-pass git history secret scan** with diff parsing. `scripts/secrets.py:72-160`

### 2.2 Gaps (ranked by accuracy impact)

| # | Gap | File reference | FN/FP impact |
|---|-----|---------------|--------------|
| G1 | No interprocedural taint (function boundaries reset scope) | `taint.py:271-276` | High FN |
| G2 | No ORM safe-call recognition (Django `.filter()`, SQLAlchemy bound params, GORM) | (missing) | High FP |
| G3 | Container/attribute/subscript taint not propagated (`d["k"]`, `obj.attr`, `lst[0]`) | `taint.py:283-286` | High FN |
| G4 | Real AST taint only for Python; JS/TS use regex; Java/Go/PHP/Ruby/C#/Rust have **no** taint logic | `taint.py:368-544` | High FN |
| G5 | Dependency CVE list is hardcoded ~196 entries, no lockfile parsing, no transitive deps | `dependency.py:25-147,367-381` | High FN |
| G6 | Missing pattern categories: LDAP injection, XXE, SSTI gadgets, deserialization gadget chains, race/TOCTOU patterns | `resources/patterns/*.json` | Medium-High FN |
| G7 | Missing secret providers: Anthropic, OpenAI `sk-proj-`, Cloudflare, Atlassian, Notion, Linear, Supabase, Firebase, Datadog, Sentry, Bitbucket, GitLab | `entropy.py:16-83` | Medium FN |
| G8 | PEM keys detected only on first `BEGIN` line; multi-line body not captured | `entropy.py:155-175` | Medium FN |
| G9 | Framework source patterns incomplete (Starlette, Quart, Koa ctx, Hapi req, Rails params) | `taint.py:25-62` | Medium FN |
| G10 | No automated false-positive filtering — three-pass protocol is purely cognitive | `sub-skills/false-positive-filter.md` | Speed/consistency risk |
| G11 | No route/endpoint extraction; entry points unknown to the scanner | `scan.py:152-161` | Medium FN |
| G12 | Reports lack code-flow walkthrough beyond raw taint path JSON | `report.py:117-128` | Reviewer friction |

---

## 3. Goals & Success Metrics

Build a benchmark before starting (Phase 0) and re-run after each phase.

| Metric | Baseline (today) | Target (end of plan) |
|--------|------------------|----------------------|
| True-positive rate on benchmark | TBD by Phase 0 | ≥ baseline + 40% |
| False-positive rate on benchmark | TBD by Phase 0 | ≤ baseline − 30% |
| Languages with real AST taint | 1 (Python) | ≥ 4 (Python, JS/TS, Java, Go) |
| CVE database freshness | hardcoded | live OSV.dev with 24h cache |
| Lockfiles parsed | 1 (Gemfile.lock) | ≥ 6 |
| Test fixtures with known vulns | ~3 files | ≥ 30 vuln + 30 safe |

---

## 4. Phased Roadmap

### Phase 0 — Benchmark Harness *(1 task, ~half a day)*

Without this, every later metric is hand-waved. Do this first.

#### Task 0.1 — Build a labeled benchmark

- **Goal**: a deterministic set of vulnerable & safe code samples with ground-truth labels.
- **Files to create**:
  - `tests/benchmark/vulnerable/<lang>/<vuln_class>_<id>.{py,js,java,go,php,rb}` — one file per known finding
  - `tests/benchmark/safe/<lang>/<scenario>_<id>.{...}` — looks-vulnerable-but-isn't (ORM-protected, sanitized, etc.)
  - `tests/benchmark/labels.json` — `{ "vulnerable/python/sqli_001.py": [{"line": 12, "cwe": 89, "type": "sqli"}], ... }`
  - `tests/benchmark/run_benchmark.py` — runs `scan.py` on the directory and computes precision/recall against `labels.json`
- **Acceptance criteria**:
  - At least 30 vulnerable + 30 safe files spanning Python, JS, Java, Go, PHP
  - `python tests/benchmark/run_benchmark.py` outputs precision/recall/F1 per vuln class
  - Current scanner's baseline numbers committed to `tests/benchmark/baseline.json`

---

### Phase 1 — High-Impact Accuracy Fixes *(5 tasks, ~1 week)*

Tackles G1, G2, G3 directly. These give the largest accuracy bump.

#### Task 1.1 — Interprocedural taint for Python

- **Goal**: track taint across function calls (within the same file, then across files).
- **File**: `scripts/taint.py`
- **Approach**:
  1. Add `FunctionSummary` dataclass: `{name, params_tainted: set[int], returns_tainted: bool, sinks_called_with_tainted: list}`.
  2. First pass: walk all `FunctionDef`/`AsyncFunctionDef` and build summaries.
  3. Second pass: when `visit_Call` hits a user-defined function, look up the summary and propagate taint based on which params were tainted.
  4. Iterate to fixpoint (max 3 iterations to avoid infinite loops on recursion).
- **Acceptance criteria**:
  - Test fixture `tests/benchmark/vulnerable/python/interprocedural_sqli.py` (taint flows: handler → helper → db.execute) detected as SQL injection.
  - No regression on existing Python taint tests.
  - Cross-file analysis behind a flag `--cross-file` (default off; enable in `scan.py` only when run-mode is `deep`).

#### Task 1.2 — Container/attribute/subscript taint

- **Goal**: propagate taint through `d["key"]`, `obj.attr`, `lst[0]`, `.get()`, `.pop()`.
- **File**: `scripts/taint.py:280-330` (`_is_tainted_value` and `visit_Assign`)
- **Approach**:
  - Extend `_is_tainted_value` to recurse into `ast.Subscript`, `ast.Attribute`, and method calls on tainted receivers.
  - Tracking model: if `request.args` is tainted, then `request.args["q"]`, `request.args.get("q")`, `data = request.args; data["q"]` all stay tainted.
  - For dicts/lists assigned from a tainted value, mark the *whole container* as tainted (over-approximate).
- **Acceptance criteria**:
  - Fixtures: `vulnerable/python/dict_subscript_sqli.py`, `vulnerable/python/attr_chain_cmdi.py` — both detected.
  - Existing FP test `test_python_no_false_positive_when_sanitized` still passes.

#### Task 1.3 — ORM safe-call recognition (FP killer)

- **Goal**: stop flagging `Model.objects.filter(name=user_input)` as SQL injection.
- **File**: `scripts/taint.py` (new section near `PY_SANITIZERS`)
- **Approach**:
  - Add `PY_ORM_SAFE_PATTERNS` dict: `{"django": ["objects.filter", "objects.get", "objects.create", "objects.update"], "sqlalchemy": ["session.query", "Query.filter", "select(", "insert(", "update("], "peewee": [...]}`
  - In `visit_Call`, before flagging a sink, check if the call chain matches a safe ORM pattern. If yes and arguments are passed by keyword (not by raw string), skip.
  - **Critical**: Django `.raw()`, `.extra()`, `RawSQL()` are still sinks (not safe). Already in `PY_SINKS` — don't break this.
- **Acceptance criteria**:
  - Fixture `safe/python/django_orm_filter.py` (uses `Model.objects.filter(q=user_input)`) → 0 findings.
  - Fixture `vulnerable/python/django_raw_sqli.py` (uses `.raw(f"SELECT ... {user_input}")`) → 1 SQL injection finding.
  - Same for SQLAlchemy: `Session.query(Model).filter(Model.name==user_input)` safe, `session.execute(text(f"...{user_input}"))` unsafe.

#### Task 1.4 — Real AST taint for JavaScript/TypeScript

- **Goal**: replace the regex-based JS analyzer with an AST analyzer.
- **File**: `scripts/taint.py:408-544`, new file `scripts/taint_js.py`
- **Approach**:
  - Use `tree-sitter-javascript` (single C extension dep, ships precompiled wheels). Add `tree-sitter` and `tree-sitter-languages` to `requirements.txt`.
  - Build a `JSTaintAnalyzer` mirroring `TaintVisitor`: track `req.body`, `req.query`, `req.params`, `req.headers`, `process.argv`, `process.env`, `req.cookies`.
  - Sinks: `eval`, `Function()`, `child_process.exec`, `child_process.spawn`, `db.query` (string interpolation), `res.redirect`, `fs.readFile/writeFile` (path), `require()` (dynamic), `Object.assign` on `req.body` (mass-assignment / proto-pollution).
  - Sanitizers: `parseInt`, `Number()`, `validator.escape`, `xss()`, `sanitize-html`, `mongoose` parameterized.
- **Acceptance criteria**:
  - Existing JS taint tests pass.
  - Fixture `vulnerable/javascript/express_sqli.js` and `vulnerable/javascript/express_proto_pollution.js` detected.
  - Fixture `safe/javascript/parameterized_query.js` → 0 findings.

#### Task 1.5 — Sanitizer expansion (Python first)

- **Goal**: Recognize 2× more sanitizers to drop FPs.
- **File**: `scripts/taint.py:115-124` (`PY_SANITIZERS`)
- **Add**:
  - SQL: `sqlalchemy.text` with named params, `psycopg2.sql.Identifier`, `psycopg2.sql.Literal`.
  - Command: `subprocess.run([...], shell=False)` (list arg, no shell), `pipes.quote`.
  - Path: `os.path.normpath` *if* followed by `startswith(safe_dir)`, `werkzeug.utils.secure_filename`.
  - XSS: `flask.Markup.escape`, `django.utils.html.escape`, `markupsafe.Markup.escape`.
  - SSRF: `ipaddress.ip_address(x).is_global` checks, `furl` parsing with allowlist.
  - Deserialization: `yaml.safe_load` (already? confirm), `json.loads` (always safe vs `pickle.loads`).
- **Acceptance criteria**:
  - Each new sanitizer has a `safe/python/<sanitizer>_<vuln>.py` fixture that yields 0 findings.

---

### Phase 2 — Pattern & Provider Expansion *(3 tasks, ~3 days)*

Tackles G6, G7, G8.

#### Task 2.1 — Pattern library expansion

- **Goal**: add missing vuln-class patterns.
- **Files**: `resources/patterns/{python,javascript,java,go,php,ruby,csharp}_patterns.json`, `generic_patterns.json`
- **Add per language**:
  - **LDAP injection**: `ldap.search`, `searchRequest`, raw filter string concatenation.
  - **XXE**: `XMLParser(resolve_entities=True)`, `etree.parse` without `resolve_entities=False`, `DocumentBuilder` without `setFeature("disallow-doctype-decl", true)`, `libxml2` raw load.
  - **SSTI**: Jinja2 `from_string`, `Template().render` over user data — already in PY_SINKS, but add for Pug, Handlebars (JS), Twig (PHP), Liquid, ERB, FreeMarker.
  - **Deserialization gadgets**: explicit list of dangerous classes (Java: `InvokerTransformer`, `TemplatesImpl`; Python: `subprocess.Popen` via `__reduce__`; .NET: `TypeNameHandling.All`).
  - **Race / TOCTOU**: `os.path.exists(p) ... open(p)`, `if not exists ... create`, separate access-check + use sequences.
  - **Open redirect**: `redirect(request.args["next"])`, `res.redirect(req.query.url)` without allowlist.
  - **NoSQL injection**: `find({"$where": user_input})`, `find(req.body)` mass-query.
- **Acceptance criteria**: each new pattern has at least one positive and one negative fixture in `tests/benchmark/`.

#### Task 2.2 — Secret-provider expansion

- **Goal**: add the 12+ missing providers.
- **File**: `scripts/utils/entropy.py:16-83` (`SECRET_PATTERNS`)
- **Add tuples** for:
  - `sk-ant-api[0-9]{2}-[A-Za-z0-9_-]{93}` → `anthropic_api_key` / critical
  - `sk-proj-[A-Za-z0-9_-]{20,}` → `openai_project_key` / high
  - `glpat-[A-Za-z0-9_-]{20}` → `gitlab_pat` / high
  - `BBDC-[A-Za-z0-9+/=]{40,}` → `bitbucket_app_password` / high
  - Cloudflare `[A-Za-z0-9_-]{40}` after `CF_API_TOKEN` literal
  - Notion `secret_[A-Za-z0-9]{43}` / Linear `lin_api_[A-Za-z0-9]{40}`
  - Supabase `sbp_[A-Za-z0-9]{40}` / `eyJ...` JWT (already covered)
  - Firebase `AAAA[A-Za-z0-9_-]{7}:APA91[A-Za-z0-9_-]{134}`
  - Datadog `[a-f0-9]{32}` after `DD_API_KEY=`
  - Sentry `https://[a-f0-9]{32}@[a-z0-9.-]+/[0-9]+` (DSN)
- **Acceptance criteria**: positive fixture for each provider in `tests/benchmark/secrets/`; `test_secret_patterns_compile` passes.

#### Task 2.3 — Multi-line PEM secret detection

- **Goal**: detect a full PEM block, not just the BEGIN line.
- **File**: `scripts/secrets.py` (line scanner is per-line; we need a file-level pass for PEMs)
- **Approach**:
  - Add a `scan_file_for_pem_blocks(text: str) -> list[Finding]` that regex-matches `-----BEGIN ([A-Z ]+)-----[\s\S]*?-----END \1-----` and emits one finding per block with `line_start`/`line_end`.
  - Call it once per file in `secrets.py` alongside the per-line scanner; dedupe by line range.
- **Acceptance criteria**: fixture with a 30-line embedded private key → exactly 1 finding spanning correct line range.

---

### Phase 3 — Multi-Language Taint *(3 tasks, ~1 week)*

Tackles G4 for the next two highest-value languages.

#### Task 3.1 — Java taint via tree-sitter

- **File**: new `scripts/taint_java.py`
- **Sources**: `@RequestParam`, `@PathVariable`, `@RequestBody`, `@RequestHeader`, `HttpServletRequest.getParameter`, `getQueryString`, `getHeader`.
- **Sinks**: `Statement.executeQuery/executeUpdate` with concatenation, `Runtime.getRuntime().exec`, `ProcessBuilder` with concatenation, `new File(userInput)`, `XPathExpression.evaluate`, `LdapContext.search`, `XMLDecoder.readObject`, `ObjectInputStream.readObject`, `FreeMarker Template.process`, `ScriptEngine.eval`.
- **Sanitizers**: `PreparedStatement.setX`, `OWASP ESAPI`, `Jsoup.clean`, `OutputEscaping`.
- **ORM safe**: Spring Data `@Query` parameterized, Hibernate `Query.setParameter`, JPA Criteria API, JdbcTemplate parameterized variants.
- **Acceptance criteria**: parity with Python — at least the SQLi/CMDI/SSTI tests work end-to-end.

#### Task 3.2 — Go taint via go/parser (or tree-sitter)

- **File**: new `scripts/taint_go.py`
- **Approach**: prefer `tree-sitter-go` over shelling out to `go/parser`. Sources: `r.URL.Query()`, `r.FormValue`, `r.Form`, `r.PostFormValue`, `r.Header`, `r.Body`, `os.Args`, `os.Getenv`. Sinks: `db.Query`/`db.Exec` with `fmt.Sprintf`, `os/exec.Command(..., args...)` with concatenation, `http.Get(userURL)`, `template.HTML(userInput)`. Sanitizers: parameterized `?` placeholders, `html/template` (auto-escape), `net/url.QueryEscape`.
- **Acceptance criteria**: 5+ benchmark fixtures detected.

#### Task 3.3 — PHP / Ruby / C# heuristic upgrade

- **Goal**: even without full AST, upgrade these from "regex per line" to "regex with variable propagation across nearby lines" (the same pattern already used for JS pre-AST).
- **File**: `scripts/taint.py:368-407`
- **Approach**: extend `analyze_with_variable_tracking()` to be language-parameterized (assignment regex per language), then call it for PHP, Ruby, C# in addition to JS. Drop AST upgrade for these to a future phase.
- **Acceptance criteria**: each language gets at least 3 fixtures detected that the pure-regex version misses.

---

### Phase 4 — Dependency & CVE Modernization *(3 tasks, ~3 days)*

Tackles G5.

#### Task 4.1 — Lockfile parsing

- **File**: `scripts/dependency.py` (extend `PARSERS` map)
- **Add**: `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`, `Pipfile.lock`, `composer.lock`, `Cargo.lock`, `go.sum`.
- **Each parser** must emit `(package, exact_version, ecosystem, is_direct: bool)` so transitive deps are flagged.
- **Acceptance criteria**: fixtures with mixed direct/transitive vulns; transitive ones now appear.

#### Task 4.2 — Live OSV.dev integration (optional, gated)

- **Goal**: replace the hardcoded list with live data from `api.osv.dev`.
- **File**: new `scripts/cve_osv.py`
- **Approach**:
  - Function `query_osv(package, version, ecosystem) -> list[Vuln]` calls `https://api.osv.dev/v1/query` with `{"package": {"name": ..., "ecosystem": ...}, "version": ...}`.
  - Cache responses in `workspace/.osv_cache/<ecosystem>/<package>@<version>.json` for 24h.
  - Falls back to hardcoded `KNOWN_VULNS` if `--offline` flag set or network fails.
  - **Privacy note**: include this in README — package names are sent to osv.dev. Should be documented and toggle-able.
- **Acceptance criteria**: with network on, scanner finds CVEs not in the hardcoded list (verified with a `requests==2.30.0` fixture).

#### Task 4.3 — Refresh hardcoded fallback list

- **Goal**: even if Task 4.2 stays gated, refresh the embedded list.
- **File**: `scripts/dependency.py:25-147`
- **Approach**: write `scripts/refresh_cve_db.py` that pulls the top-200 packages per ecosystem from OSV and emits an updated `KNOWN_VULNS` dict. Run quarterly (manual cron or GitHub Action).
- **Acceptance criteria**: list grows to ≥500 entries; date stamp comment at the top of `KNOWN_VULNS`.

---

### Phase 5 — Orchestration, Reporting & UX *(3 tasks, ~3 days)*

Tackles G10, G11, G12.

#### Task 5.1 — Route/endpoint extraction

- **File**: new `scripts/routes.py`, called from `scan.py` after framework detection (`scan.py:152-161`).
- **Approach**: per detected framework, regex-or-AST-extract route definitions:
  - Flask: `@app.route("/x")`, `@bp.route(...)`, `methods=[...]`
  - Django: `urlpatterns = [path("x", view), ...]`
  - FastAPI: `@app.get("/x")`, `@app.post(...)`
  - Express: `app.get("/x", handler)`, `router.post(...)`
  - Spring: `@GetMapping`, `@PostMapping`, `@RequestMapping`
  - Persist routes table in SQLite (`workspace/scan_state.db`) so reports can reference entry points.
- **Acceptance criteria**: scanning a Flask app produces a list of routes in the report's executive summary; each finding's report includes the nearest route.

#### Task 5.2 — Code-flow steps in reports

- **File**: `scripts/report.py:117-128`
- **Approach**:
  - Extend taint-path JSON schema: `[{step, file, line, code_snippet, role: "source"|"propagator"|"sink"|"sanitizer-bypass"}]`.
  - In MD/HTML output, render as a numbered walkthrough with the snippet at each step.
  - In SARIF, emit `codeFlows` element (SARIF 2.1.0 supports this natively).
- **Acceptance criteria**: a sample finding's HTML report shows a 3-step walkthrough; SARIF has a `codeFlows` array that GitHub Code Scanning renders correctly.

#### Task 5.3 — Sub-skill orchestration helper

- **Goal**: reduce reliance on the agent reading 19 sub-skills serially. Provide a script that presents the relevant sub-skill prompt + the candidate findings + the file slice in one structured payload.
- **File**: new `scripts/orchestrate.py`
- **Approach**:
  - Reads `workspace/scan_state.db`, groups candidates by phase (taint → input-validator → auth → ...).
  - For each phase, emits a JSON object: `{phase, sub_skill_path, findings: [...], code_excerpts: {file: [(line_start, line_end, snippet)]}}`.
  - Agent consumes phase-by-phase rather than re-reading every sub-skill from scratch.
- **Acceptance criteria**: `python scripts/orchestrate.py --phase taint` outputs a self-contained JSON the agent can act on without touching disk for sub-skill content.

---

## 5. Cross-Cutting Concerns

### 5.1 Testing Strategy

Every task above has an **Acceptance criteria** clause that names fixtures to add. Two test layers:

1. **Unit tests** (`tests/test_scripts.py`) — keep fast, target individual functions.
2. **Benchmark suite** (`tests/benchmark/`) — slower, runs end-to-end, measures precision/recall.

Add to CI (`.github/workflows/ci.yml`):
- New `benchmark` job that runs only on `main` push (not every PR) and posts metrics as a workflow summary.
- Fail the run if precision drops > 5% or recall drops > 5% vs. `tests/benchmark/baseline.json`.

### 5.2 Performance Budget

After all phases, full scan of a 100kLOC repo must complete in < 2× current time on the same hardware. Profile before/after Phase 1 and Phase 3 (the most expensive additions). If over budget, gate the heavy passes behind `--deep` (default off).

### 5.3 Backwards Compatibility

- `scan.py` CLI flags must stay stable; new flags can be added but defaults must not change behavior.
- Report JSON schema bumps to v1.1.0 in Task 5.2 (additive only — don't remove fields).
- SQLite schema migrations live in `scripts/utils/db.py`; add a `schema_version` table.

---

## 6. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| tree-sitter wheels missing for some platforms | Med | Med | Keep regex analyzer as fallback path; detect import failure and warn |
| OSV.dev rate limiting in CI | Med | Low | Local cache + `--offline` flag + skip in CI by default |
| Interprocedural fixpoint diverges on recursion | Low | Med | Hard cap at 3 iterations; log and bail out |
| ORM allowlist whitelists too aggressively → FNs | Med | Med | Only whitelist when keyword args used, never positional with strings |
| Pattern expansion increases false positives | High | Low–Med | Every new pattern requires both a positive and a negative fixture; benchmark gate in CI |
| Live CVE DB makes scanner non-deterministic | Med | Low | Cache pinned per scan; `--offline` for reproducible runs |

---

## 7. Out of Scope (for this plan)

The following are real gaps but left for a later iteration:

- **Symbolic execution / SMT-based path feasibility** — too heavy for the agentic-skill use case.
- **Full call-graph extraction across compiled binaries** — only source available.
- **Mobile native binary analysis** (Android dex / iOS Mach-O) — `mobile-security-reviewer` stays source-only.
- **C/C++ memory-safety taint** — `memory-safety-analyzer` keeps its current pattern approach.
- **Differential analysis between commits / PR-mode scanning** — useful but separate from accuracy.

---

## 8. Suggested Execution Order (TL;DR for the implementer)

1. **Phase 0** first — without the benchmark, you can't prove the rest worked.
2. **Phase 1** in order (1.1 → 1.2 → 1.3 → 1.4 → 1.5) — each builds on the previous.
3. **Phase 2** can be parallelized (2.1, 2.2, 2.3 independent).
4. **Phase 3** after Phase 1 (mirrors the Python design).
5. **Phase 4** can run in parallel with Phase 3 (different subsystem).
6. **Phase 5** last — relies on everything above producing data.

After each phase: run benchmark, commit metrics to `tests/benchmark/results/<phase>.json`, update README badges.
