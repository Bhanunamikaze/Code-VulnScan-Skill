# Contributing to Code-VulnScan Skill

Thank you for helping make this scanner better. This guide covers the four most common contribution types.

---

## 1. Adding a Language Pattern File

Pattern files live in `resources/patterns/<language>_patterns.json`. Each file is a JSON object where keys are vulnerability categories and values are arrays of pattern entries.

### Entry schema

```json
{
  "id": "py_sqli_001",
  "regex": "execute\\s*\\(\\s*f[\"']",
  "vuln_type": "sqli",
  "severity": "high",
  "title": "SQL injection via f-string",
  "description": "User-controlled data in a format string passed to execute() allows SQLi.",
  "remediation": "Use parameterized queries: cursor.execute(sql, (param,))",
  "references": ["CWE-89", "OWASP-A03"],
  "false_positive_risk": "low"
}
```

Required fields: `id`, `regex`, `vuln_type`, `severity`, `title`.

### Naming conventions

- `id`: `<lang>_<category>_<3-digit-seq>` — e.g. `py_sqli_003`, `go_cmdi_001`
- `vuln_type`: use the standard set: `sqli`, `cmdi`, `xss`, `path_traversal`, `ssrf`, `xxe`, `deserialization`, `crypto`, `open_redirect`, `race_condition`, `redos`, `secrets`
- `severity`: `critical`, `high`, `medium`, `low`

### Regex guidelines

- Anchor generously — `\bos\.system\s*\(` not `system(`
- Use `(?i)` for case-insensitive matching where the language is case-insensitive
- Test your regex against both true positives and expected false positives
- Avoid unbounded `.*` — prefer `[^"'\n]{0,200}`
- Run `python3 -c "import re; re.compile(r'YOUR_PATTERN')"` before submitting

### Steps

1. Edit or create `resources/patterns/<lang>_patterns.json`
2. Validate JSON: `python3 -c "import json; json.load(open('resources/patterns/<lang>_patterns.json'))"`
3. Add a test in `tests/test_scripts.py` (see `TestPatternMatching` class)
4. Add a vulnerable fixture in `tests/fixtures/vuln_<lang>.<ext>` with a comment marking the vulnerable line
5. Run `python3 -m pytest tests/ -v -k "Pattern"`

---

## 2. Adding a Sub-Skill

Sub-skills live in `sub-skills/<name>.md`. They are specialist analysis agents invoked by the main SKILL.md orchestrator.

### Template

```markdown
# <Sub-Skill Name>

**Role**: One-sentence description of what this agent does.

**Trigger**: When the orchestrator should call this sub-skill.

---

## Detection Checklist

### <Category>
- [ ] Check 1 — what to look for, what makes it exploitable
- [ ] Check 2

## Severity Classification

| Finding | CVSS Range | Notes |
|---------|-----------|-------|
| ...     | ...       | ...   |

## Remediation Patterns

### <Vuln Type>
**Vulnerable**:
```code example```
**Safe**:
```code example```

## References
- CWE-XXX
- OWASP category
```

### Steps

1. Create `sub-skills/<name>.md`
2. Add an entry to `SKILL.md` in the sub-skills dispatch table (the `## Sub-Skills` section)
3. Update the architecture tree in `README.md`
4. Update `docs/tasks.md`

---

## 3. Adding a CVE Entry

CVE entries live in `scripts/dependency.py` in the `KNOWN_VULNS` dict.

### Entry format

```python
("package-name", "<vulnerable.range|<other.range", ">=safe.version", "CVE-YYYY-NNNNN", cvss_score, "vuln_type", "Short description"),
```

- `package-name`: lowercase, exactly as it appears in the manifest (e.g. `"log4j-core"`, `"django"`)
- `vulnerable range`: pipe-separated comparisons — `"<2.0.0|<1.9.5"` means "< 2.0.0 OR < 1.9.5"
- `cvss_score`: float, NVD base score
- `vuln_type`: same standard set as patterns (see above)

### Requirements before adding

- CVE must be published on NVD (https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNNN)
- Include the correct affected version range from the NVD or package advisory
- Include the first safe version
- Add a test in `TestCVEDetection` or verify with `python3 scripts/dependency.py --path <dir-with-manifest>`

### Steps

1. Add to the correct ecosystem list in `KNOWN_VULNS`
2. Verify `version_in_range()` handles your range correctly
3. Add a `TestCVEDetection` test case if the package is not already covered
4. Run `python3 -m pytest tests/ -v -k "CVE"`

---

## 4. Adding an IDE Install Target

Install targets live in `install.sh` and `install.ps1`.

### install.sh pattern

```bash
install_myide() {
    local project_dir="${1:-$(pwd)}"
    local dest="$project_dir/.myide/instructions.md"
    mkdir -p "$(dirname "$dest")"
    {
        echo "# Code-VulnScan Instructions"
        echo ""
        _skill_invocation_text
    } > "$dest"
    echo "  ✓ MyIDE: $dest"
}
```

Add your function to the `case "$TARGET"` dispatch block and to the `project` and `all` branches.

Mirror the same logic in `install.ps1` following the existing `Install-*` function pattern.

### Steps

1. Research the IDE's native instruction format (e.g. MDC frontmatter for Cursor, `.prompt` files for Continue)
2. Implement `install_<name>()` in `install.sh` and `Install-<Name>` in `install.ps1`
3. Add to `--target` help text and to `project`/`all` targets
4. Test: `bash install.sh --target <name> --project-dir /tmp/test-install && ls /tmp/test-install`
5. Update the IDE compatibility table in `README.md`

---

## Testing

```bash
# Full test suite
python3 -m pytest tests/ -v

# Single class
python3 -m pytest tests/ -v -k "TestEntropy"

# With coverage
python3 -m pytest tests/ --cov=scripts --cov-report=term-missing
```

Fixtures in `tests/fixtures/` are intentionally vulnerable files. Do not deploy them. Each fixture should include the comment `# Intentionally vulnerable — used for test fixtures ONLY` at the top.

## PR Checklist

- [ ] JSON pattern files are valid (`json.load` succeeds)
- [ ] All regexes compile without error
- [ ] New code has at least one test
- [ ] `python3 -m pytest tests/ -v` passes
- [ ] `docs/tasks.md` updated if a tracked task is completed
- [ ] No real credentials, keys, or secrets in any committed file
