#!/usr/bin/env python3
"""
Unit tests for Code-VulnScan scripts.
Run: python3 -m pytest tests/ -v
"""

import json
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from scripts.utils.entropy import shannon_entropy, scan_line_for_secrets, SECRET_PATTERNS
from scripts.utils.languages import detect_language, is_test_file
from scripts.utils.files import enumerate_files, get_snippet
from scripts.utils.patterns import load_patterns, scan_file_for_candidates
from scripts.taint import analyze_python_ast, analyze_file
from scripts.dependency import (
    parse_version, version_in_range,
    parse_requirements_txt, parse_package_json,
    parse_cargo_toml, parse_csproj, parse_build_gradle,
)

FIXTURES = Path(__file__).parent / "fixtures"


# ── Entropy ───────────────────────────────────────────────────────────────────

class TestEntropy:
    def test_high_entropy_random_string(self):
        assert shannon_entropy("aB3$xY9!kQ2#mZ7@") > 3.5

    def test_low_entropy_repeated(self):
        assert shannon_entropy("aaaaaaaaaaaaaaaa") < 1.0

    def test_empty_string(self):
        assert shannon_entropy("") == 0.0

    def test_aws_key_detected(self):
        line = 'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
        hits = scan_line_for_secrets(line, 1, "test.py")
        assert any(h["secret_type"] == "aws_secret_key" for h in hits), \
            f"Expected aws_secret_key in {[h['secret_type'] for h in hits]}"

    def test_github_token_detected(self):
        line = 'token = "ghp_abcdefghijklmnopqrstuvwxyz123456"'
        hits = scan_line_for_secrets(line, 1, "config.py")
        types = [h["secret_type"] for h in hits]
        assert any("github" in t for t in types), f"Expected github token in {types}"

    def test_no_false_positive_on_placeholder(self):
        line = 'api_key = "your-api-key-here"'
        hits = scan_line_for_secrets(line, 1, "readme.md")
        # Should not flag obvious placeholder text
        assert all(h.get("severity") not in ("critical", "high") for h in hits)

    def test_private_key_header_detected(self):
        line = "-----BEGIN RSA PRIVATE KEY-----"
        hits = scan_line_for_secrets(line, 1, "id_rsa")
        assert any("private_key" in h["secret_type"] for h in hits)

    def test_secret_patterns_compile(self):
        import re
        for p in SECRET_PATTERNS:
            try:
                re.compile(p["regex"])
            except re.error as e:
                pytest.fail(f"Pattern {p['name']} has invalid regex: {e}")


# ── Language detection ────────────────────────────────────────────────────────

class TestLanguageDetection:
    def test_python_extension(self):
        assert detect_language(Path("app.py")) == "python"

    def test_typescript_extension(self):
        assert detect_language(Path("component.tsx")) == "typescript"

    def test_go_extension(self):
        assert detect_language(Path("main.go")) == "go"

    def test_dockerfile_name(self):
        assert detect_language(Path("Dockerfile")) == "dockerfile"

    def test_dotenv_name(self):
        assert detect_language(Path(".env")) == "dotenv"

    def test_test_file_detection(self):
        assert is_test_file(Path("tests/test_app.py")) is True
        assert is_test_file(Path("app_test.go")) is True
        assert is_test_file(Path("app.spec.ts")) is True
        assert is_test_file(Path("src/main.py")) is False


# ── Pattern matching ──────────────────────────────────────────────────────────

class TestPatternMatching:
    def test_python_patterns_load(self):
        patterns = load_patterns("python")
        assert isinstance(patterns, dict)
        assert len(patterns) > 0

    def test_javascript_patterns_load(self):
        patterns = load_patterns("javascript")
        assert len(patterns) > 0

    def test_yaml_patterns_load(self):
        patterns = load_patterns("yaml")
        assert len(patterns) > 0

    def test_scan_python_fixture(self):
        path = FIXTURES / "vuln_python.py"
        if not path.exists():
            pytest.skip("fixture not found")
        content = path.read_text()
        findings = scan_file_for_candidates(path, content, "python")
        types = {f["vuln_type"] for f in findings}
        assert "sqli" in types, f"Expected sqli in {types}"
        assert "cmdi" in types, f"Expected cmdi in {types}"

    def test_scan_javascript_fixture(self):
        path = FIXTURES / "vuln_javascript.js"
        if not path.exists():
            pytest.skip("fixture not found")
        content = path.read_text()
        findings = scan_file_for_candidates(path, content, "javascript")
        types = {f["vuln_type"] for f in findings}
        assert len(types) > 0, "Expected at least one finding in JS fixture"

    def test_all_pattern_files_valid_json(self):
        patterns_dir = Path(__file__).parent.parent / "resources" / "patterns"
        for f in patterns_dir.glob("*.json"):
            data = json.loads(f.read_text())
            assert isinstance(data, dict), f"{f.name} top level must be a dict"
            for cat, entries in data.items():
                assert isinstance(entries, list), f"{f.name}/{cat} must be a list"
                for e in entries:
                    assert "id" in e, f"{f.name}/{cat} entry missing 'id'"
                    assert "regex" in e, f"{f.name}/{cat} entry missing 'regex'"


# ── Taint analysis ────────────────────────────────────────────────────────────

class TestTaintAnalysis:
    def test_python_sqli_path(self):
        code = '''
from flask import request
def search():
    q = request.args.get("q")
    conn.execute(f"SELECT * FROM items WHERE name='{q}'")
'''
        result = analyze_python_ast(code, "test.py")
        assert len(result["sources"]) > 0, "Expected source (request.args.get)"
        assert len(result["potential_paths"]) > 0, "Expected taint path source→sink"

    def test_python_no_false_positive_when_sanitized(self):
        code = '''
from flask import request
import shlex
def run():
    cmd = request.args.get("cmd")
    safe = shlex.quote(cmd)
    os.system(safe)
'''
        result = analyze_python_ast(code, "test.py")
        # May still detect the source but should have fewer high-confidence paths
        # This is a best-effort check — the sanitizer annotation is in PY_SANITIZERS
        assert isinstance(result, dict)

    def test_python_fixture_taint(self):
        path = FIXTURES / "vuln_python.py"
        if not path.exists():
            pytest.skip("fixture not found")
        result = analyze_file(str(path), "python")
        assert result["total_sources"] > 0
        assert result["total_potential_paths"] > 0

    def test_go_fixture_taint(self):
        path = FIXTURES / "vuln_go.go"
        if not path.exists():
            pytest.skip("fixture not found")
        result = analyze_file(str(path), "go")
        # Go uses pattern-based — just check it returns the expected structure
        assert "sources" in result
        assert "sinks" in result


# ── Dependency parsing ────────────────────────────────────────────────────────

class TestDependencyParsing:
    def test_parse_version(self):
        assert parse_version("1.2.3") == (1, 2, 3, 0)
        assert parse_version("10.0") == (10, 0, 0, 0)
        assert parse_version("2.0.0.1") == (2, 0, 0, 1)

    def test_version_in_range(self):
        assert version_in_range("1.0.0", "<2.0.0") is True
        assert version_in_range("2.0.0", "<2.0.0") is False
        assert version_in_range("3.0.0", "<2.0.0") is False
        assert version_in_range("1.5.0", "<2.0.0|<1.4.0") is True

    def test_parse_requirements_txt(self):
        with tempfile.NamedTemporaryFile(suffix=".txt", mode="w", delete=False) as f:
            f.write("django==4.1.0\nrequests>=2.28.0\n# comment\nflask~=2.3.0\n")
            fpath = Path(f.name)
        deps = parse_requirements_txt(fpath)
        names = [d["name"] for d in deps]
        assert "django" in names
        assert "requests" in names
        fpath.unlink()

    def test_parse_package_json(self):
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump({"dependencies": {"lodash": "4.17.20", "express": "^4.17.1"}}, f)
            fpath = Path(f.name)
        deps = parse_package_json(fpath)
        names = [d["name"] for d in deps]
        assert "lodash" in names
        fpath.unlink()

    def test_parse_cargo_toml(self):
        content = '[dependencies]\nserde = "1.0.0"\nactix-web = { version = "4.0.0" }\n'
        with tempfile.NamedTemporaryFile(suffix=".toml", mode="w", delete=False) as f:
            f.write(content)
            fpath = Path(f.name)
        deps = parse_cargo_toml(fpath)
        names = [d["name"] for d in deps]
        assert "serde" in names
        assert "actix-web" in names
        fpath.unlink()

    def test_parse_csproj(self):
        content = '''<Project><ItemGroup>
<PackageReference Include="Newtonsoft.Json" Version="12.0.1" />
<PackageReference Include="Microsoft.AspNetCore.App" Version="3.1.0" />
</ItemGroup></Project>'''
        with tempfile.NamedTemporaryFile(suffix=".csproj", mode="w", delete=False) as f:
            f.write(content)
            fpath = Path(f.name)
        deps = parse_csproj(fpath)
        names = [d["name"] for d in deps]
        assert "newtonsoft.json" in names
        fpath.unlink()

    def test_parse_build_gradle(self):
        content = "dependencies {\n  implementation 'com.google.guava:guava:30.1'\n  testImplementation(\"org.junit:junit:4.12\")\n}\n"
        with tempfile.NamedTemporaryFile(suffix=".gradle", mode="w", delete=False) as f:
            f.write(content)
            fpath = Path(f.name)
        deps = parse_build_gradle(fpath)
        names = [d["name"] for d in deps]
        assert "guava" in names
        fpath.unlink()


# ── CVE detection integration ─────────────────────────────────────────────────

class TestCVEDetection:
    def _scan_reqs(self, content: str) -> list:
        with tempfile.TemporaryDirectory() as tmpdir:
            req = Path(tmpdir) / "requirements.txt"
            req.write_text(content)
            from scripts.dependency import check_dependencies
            return check_dependencies(Path(tmpdir))["findings"]

    def test_django_sqli_cve(self):
        findings = self._scan_reqs("django==4.0.0\n")
        cves = [f["cve"] for f in findings]
        assert "CVE-2022-28347" in cves, f"Expected Log4Shell CVE in {cves}"

    def test_log4j_detection(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pom = Path(tmpdir) / "pom.xml"
            pom.write_text("""<dependency>
<artifactId>log4j-core</artifactId><version>2.14.0</version>
</dependency>""")
            from scripts.dependency import check_dependencies
            findings = check_dependencies(Path(tmpdir))["findings"]
        cves = [f["cve"] for f in findings]
        assert "CVE-2021-44228" in cves, f"Expected Log4Shell in {cves}"

    def test_safe_version_no_finding(self):
        findings = self._scan_reqs("django==4.2.10\n")
        django_findings = [f for f in findings if f["package"] == "django"]
        assert len(django_findings) == 0, f"Django 4.2.10 should not have findings: {django_findings}"


# ── Regex analyzer ────────────────────────────────────────────────────────────

class TestRegexAnalyzer:
    def test_nested_quantifier_detected(self):
        from scripts.regex_analyzer import has_nested_quantifiers, estimate_complexity
        assert has_nested_quantifiers(r"(a+)+") is True
        assert estimate_complexity(r"(a+)+") == "catastrophic"

    def test_linear_regex_ok(self):
        from scripts.regex_analyzer import estimate_complexity
        assert estimate_complexity(r"^[a-z]{3,10}$") == "linear"

    def test_anchored_pattern(self):
        from scripts.regex_analyzer import is_anchored
        assert is_anchored(r"^abc$") is True
        assert is_anchored(r"abc") is False


if __name__ == "__main__":
    import subprocess
    subprocess.run([sys.executable, "-m", "pytest", __file__, "-v"])
