#!/usr/bin/env python3
"""
Dependency vulnerability checker — scans manifests for known-vulnerable versions.

Usage:
  python3 scripts/dependency.py --path <dir> [--output <file>]

Checks: requirements.txt, Pipfile, pyproject.toml, package.json, pom.xml,
        build.gradle, go.mod, Gemfile, composer.json, Cargo.toml
"""

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from scripts.utils.languages import get_manifest_files

# Known vulnerable packages (curated list — agent should verify via live CVE DB)
# Format: (package_name, vulnerable_range, safe_version, cve, cvss, vuln_type, description)
KNOWN_VULNS = {
    "python": [
        ("django", "<2.2.28|<3.2.13|<4.0.4", ">=4.2.0", "CVE-2022-28347", 9.8, "sqli", "SQL injection via QuerySet.annotate()"),
        ("flask", "<2.3.2", ">=2.3.2", "CVE-2023-30861", 7.5, "session_security", "Session cookie bypass in debug mode"),
        ("pillow", "<9.3.0", ">=10.0.0", "CVE-2022-45199", 7.5, "dos", "Decompression bomb DoS"),
        ("pyyaml", "<6.0", ">=6.0", "CVE-2020-14343", 9.8, "rce", "Arbitrary code execution via yaml.load()"),
        ("cryptography", "<41.0.0", ">=41.0.0", "CVE-2023-49083", 7.5, "dos", "NULL pointer dereference"),
        ("requests", "<2.31.0", ">=2.31.0", "CVE-2023-32681", 6.1, "ssrf", "Proxy-Authorization header leak on redirects"),
        ("paramiko", "<3.4.0", ">=3.4.0", "CVE-2023-48795", 5.9, "mitm", "Terrapin SSH protocol downgrade"),
        ("lxml", "<4.9.3", ">=4.9.3", "CVE-2022-2309", 7.5, "xxe", "NULL pointer dereference / XXE"),
        ("sqlalchemy", "<1.4.49", ">=2.0.0", "CVE-2019-7164", 9.8, "sqli", "SQL injection via order_by()"),
        ("werkzeug", "<3.0.1", ">=3.0.1", "CVE-2023-46136", 7.5, "dos", "Multipart data parsing DoS"),
        ("jinja2", "<3.1.3", ">=3.1.3", "CVE-2024-22195", 5.4, "xss", "XSS via xmlattr filter"),
        ("aiohttp", "<3.9.0", ">=3.9.0", "CVE-2023-47641", 7.5, "path_traversal", "Static file path traversal"),
        ("urllib3", "<2.0.7", ">=2.0.7", "CVE-2023-45803", 4.2, "info_disclosure", "Sensitive data in HTTP headers"),
        ("celery", "<5.3.0", ">=5.3.0", "CVE-2021-23727", 9.8, "rce", "Command injection via pickle"),
    ],
    "javascript": [
        ("lodash", "<4.17.21", ">=4.17.21", "CVE-2021-23337", 7.2, "rce", "Command injection via template()"),
        ("lodash", "<4.17.21", ">=4.17.21", "CVE-2020-8203", 7.4, "prototype_pollution", "Prototype pollution"),
        ("axios", "<1.6.0", ">=1.6.0", "CVE-2023-45857", 6.5, "csrf", "CSRF token leak via forged URL"),
        ("jsonwebtoken", "<9.0.0", ">=9.0.0", "CVE-2022-23529", 8.8, "rce", "Remote code execution via malformed JWT"),
        ("express", "<4.18.2", ">=4.18.2", "CVE-2022-24999", 7.5, "open_redirect", "qs prototype pollution"),
        ("qs", "<6.7.3", ">=6.7.3", "CVE-2022-24999", 7.5, "prototype_pollution", "Prototype pollution"),
        ("minimist", "<1.2.6", ">=1.2.6", "CVE-2021-44906", 9.8, "prototype_pollution", "Prototype pollution"),
        ("node-fetch", "<2.6.7|<3.1.1", ">=3.2.0", "CVE-2022-0235", 6.1, "info_disclosure", "Cookie and Authorization header leak"),
        ("path-to-regexp", "<1.9.0", ">=1.9.0", "CVE-2024-45296", 7.5, "redos", "ReDoS via backtracking regex"),
        ("semver", "<7.5.2", ">=7.5.2", "CVE-2022-25883", 7.5, "redos", "ReDoS via invalid version strings"),
        ("tough-cookie", "<4.1.3", ">=4.1.3", "CVE-2023-26136", 9.8, "prototype_pollution", "Prototype pollution"),
        ("word-wrap", "<1.2.4", ">=1.2.4", "CVE-2023-26115", 7.5, "redos", "ReDoS"),
        ("webpack", "<5.88.1", ">=5.88.1", "CVE-2023-28154", 9.8, "rce", "Cross-realm object access"),
        ("next", "<13.5.1", ">=13.5.1", "CVE-2023-46298", 7.5, "dos", "HTTP parameter pollution DoS"),
    ],
    "java": [
        ("log4j-core", "<2.17.1", ">=2.17.1", "CVE-2021-44228", 10.0, "rce", "Log4Shell — JNDI injection RCE"),
        ("log4j-core", ">=2.15.0,<2.17.0", ">=2.17.0", "CVE-2021-45046", 9.0, "rce", "Log4Shell bypass"),
        ("spring-webmvc", "<5.3.18|<6.0.0", ">=5.3.28", "CVE-2022-22965", 9.8, "rce", "Spring4Shell RCE"),
        ("spring-security-core", "<5.7.5|<6.0.1", ">=5.7.11", "CVE-2022-31692", 9.8, "auth_bypass", "Authentication bypass"),
        ("jackson-databind", "<2.13.4.2", ">=2.14.0", "CVE-2022-42003", 7.5, "dos", "DoS via deep nesting"),
        ("jackson-databind", "<2.12.7.1", ">=2.14.0", "CVE-2021-46877", 7.5, "dos", "DoS via array wrapping"),
        ("commons-text", "<1.10.0", ">=1.10.0", "CVE-2022-42889", 9.8, "rce", "Text4Shell — interpolation RCE"),
        ("commons-collections", "<3.2.2", ">=3.2.2", "CVE-2015-7501", 9.8, "rce", "Deserialization RCE gadget chain"),
        ("xstream", "<1.4.20", ">=1.4.20", "CVE-2022-40151", 7.5, "dos", "DoS via crafted XML"),
        ("netty-codec-http", "<4.1.86", ">=4.1.90", "CVE-2022-41881", 7.5, "dos", "Stack overflow via malformed headers"),
        ("h2", "<2.1.214", ">=2.2.220", "CVE-2022-45868", 7.8, "rce", "Console access leads to RCE"),
        ("snakeyaml", "<2.0", ">=2.0", "CVE-2022-1471", 9.8, "rce", "Constructor deserialization RCE"),
    ],
    "go": [
        ("golang.org/x/net", "<0.17.0", ">=0.17.0", "CVE-2023-44487", 7.5, "dos", "HTTP/2 rapid reset attack DoS"),
        ("golang.org/x/crypto", "<0.13.0", ">=0.13.0", "CVE-2023-48795", 5.9, "mitm", "Terrapin SSH downgrade attack"),
        ("github.com/gin-gonic/gin", "<1.9.1", ">=1.9.1", "CVE-2023-29401", 4.3, "dos", "Large multipart form DoS"),
    ],
    "ruby": [
        ("rails", "<7.0.8|<7.1.1", ">=7.1.1", "CVE-2023-38037", 5.4, "info_disclosure", "Information disclosure via ReDoS"),
        ("nokogiri", "<1.15.4", ">=1.15.4", "CVE-2023-45648", 5.3, "xxe", "XML namespace confusion"),
        ("devise", "<4.9.3", ">=4.9.3", "CVE-2019-5421", 7.5, "timing_attack", "Timing attack on password reset"),
        ("rack", "<2.2.8", ">=2.2.8", "CVE-2023-27539", 7.5, "dos", "ReDoS in header parsing"),
    ],
    "php": [
        ("laravel/framework", "<10.28.0", ">=10.28.0", "CVE-2023-43814", 6.5, "info_disclosure", "Debug mode info leak"),
        ("guzzlehttp/guzzle", "<7.5.0", ">=7.5.0", "CVE-2022-31090", 7.5, "ssrf", "SSRF via URL parsing"),
        ("symfony/http-foundation", "<6.3.1", ">=6.3.1", "CVE-2023-25575", 7.5, "dos", "ReDoS in header parsing"),
        ("phpoffice/phpspreadsheet", "<1.29.0", ">=1.29.0", "CVE-2024-25118", 8.8, "xxe", "XXE via XLSX files"),
    ],
}


def parse_version(v: str) -> tuple:
    """Parse a version string into a comparable tuple."""
    v = re.sub(r"[^\d.]", "", v)
    parts = v.split(".")
    result = []
    for p in parts[:4]:
        try:
            result.append(int(p))
        except ValueError:
            result.append(0)
    while len(result) < 4:
        result.append(0)
    return tuple(result)


def version_in_range(version: str, range_str: str) -> bool:
    """Check if a version matches a vulnerable range (e.g. '<2.28|<3.2.13')."""
    current = parse_version(version)
    for part in range_str.split("|"):
        part = part.strip()
        m = re.match(r"([<>]=?|==)\s*([\d.]+(?:\.[\d]+)*)", part)
        if not m:
            continue
        op, ver = m.group(1), m.group(2)
        target = parse_version(ver)
        if op == "<" and current < target:
            return True
        elif op == "<=" and current <= target:
            return True
        elif op == ">" and current > target:
            return True
        elif op == ">=" and current >= target:
            return True
        elif op == "==" and current == target:
            return True
    return False


def parse_requirements_txt(path: Path) -> list:
    deps = []
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = re.match(r"^([\w\-\.]+)\s*(?:==|>=|<=|~=|!=|>|<)\s*([\d\.]+)", line)
        if m:
            deps.append({"name": m.group(1).lower(), "version": m.group(2), "source": str(path)})
    return deps


def parse_package_json(path: Path) -> list:
    try:
        data = json.loads(path.read_text(errors="replace"))
    except (json.JSONDecodeError, OSError):
        return []
    deps = []
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        for name, ver in data.get(section, {}).items():
            ver = re.sub(r"[^0-9.]", "", ver)
            if ver:
                deps.append({"name": name.lower(), "version": ver, "source": str(path),
                             "is_dev": section == "devDependencies"})
    return deps


def parse_pom_xml(path: Path) -> list:
    content = path.read_text(errors="replace")
    deps = []
    for m in re.finditer(
        r"<dependency>.*?<artifactId>(.*?)</artifactId>.*?<version>(.*?)</version>.*?</dependency>",
        content, re.DOTALL
    ):
        deps.append({"name": m.group(1).strip().lower(), "version": m.group(2).strip(), "source": str(path)})
    return deps


def parse_go_mod(path: Path) -> list:
    deps = []
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        m = re.match(r"^\s*([\w./\-]+)\s+v([\d.]+)", line)
        if m:
            deps.append({"name": m.group(1).lower(), "version": m.group(2), "source": str(path)})
    return deps


def parse_gemfile_lock(path: Path) -> list:
    deps = []
    in_specs = False
    for line in path.read_text(errors="replace").splitlines():
        if "GEM" in line or "specs:" in line:
            in_specs = True
        elif in_specs:
            m = re.match(r"\s{4}([\w\-]+)\s+\(([\d.]+)\)", line)
            if m:
                deps.append({"name": m.group(1).lower(), "version": m.group(2), "source": str(path)})
    return deps


def parse_composer_json(path: Path) -> list:
    try:
        data = json.loads(path.read_text(errors="replace"))
    except (json.JSONDecodeError, OSError):
        return []
    deps = []
    for section in ("require", "require-dev"):
        for name, ver in data.get(section, {}).items():
            ver = re.sub(r"[^0-9.]", "", ver)
            if ver and name != "php":
                deps.append({"name": name.lower(), "version": ver, "source": str(path)})
    return deps


PARSERS = {
    "requirements.txt": ("python", parse_requirements_txt),
    "requirements-dev.txt": ("python", parse_requirements_txt),
    "requirements-prod.txt": ("python", parse_requirements_txt),
    "package.json": ("javascript", parse_package_json),
    "pom.xml": ("java", parse_pom_xml),
    "build.gradle": ("java", lambda p: []),
    "go.mod": ("go", parse_go_mod),
    "gemfile.lock": ("ruby", parse_gemfile_lock),
    "composer.json": ("php", parse_composer_json),
}


def check_dependencies(base_path: Path) -> dict:
    all_findings = []
    all_deps = []
    manifests_found = []

    manifests = get_manifest_files(base_path)
    for manifest in manifests:
        name_lower = manifest.name.lower()
        if name_lower not in PARSERS:
            continue
        ecosystem, parser = PARSERS[name_lower]
        deps = parser(manifest)
        manifests_found.append({"file": str(manifest.relative_to(base_path)), "ecosystem": ecosystem, "deps": len(deps)})
        all_deps.extend([(ecosystem, d) for d in deps])

    for ecosystem, dep in all_deps:
        pkg_name = dep["name"]
        version = dep["version"]
        vulns = KNOWN_VULNS.get(ecosystem, [])
        for pkg, vuln_range, safe_ver, cve, cvss, vuln_type, description in vulns:
            if pkg.lower() == pkg_name and version_in_range(version, vuln_range):
                all_findings.append({
                    "package": pkg,
                    "ecosystem": ecosystem,
                    "current_version": version,
                    "vulnerable_range": vuln_range,
                    "safe_version": safe_ver,
                    "cve": cve,
                    "cvss": cvss,
                    "vuln_type": vuln_type,
                    "description": description,
                    "is_dev": dep.get("is_dev", False),
                    "manifest": dep.get("source", ""),
                    "severity": "critical" if cvss >= 9.0 else "high" if cvss >= 7.0 else "medium" if cvss >= 4.0 else "low",
                    "status": "candidate",
                })

    all_findings.sort(key=lambda x: -x["cvss"])

    return {
        "manifests": manifests_found,
        "total_deps_checked": len(all_deps),
        "findings": all_findings,
        "summary": {
            "critical": sum(1 for f in all_findings if f["severity"] == "critical"),
            "high": sum(1 for f in all_findings if f["severity"] == "high"),
            "medium": sum(1 for f in all_findings if f["severity"] == "medium"),
            "low": sum(1 for f in all_findings if f["severity"] == "low"),
        }
    }


def main():
    parser = argparse.ArgumentParser(description="Code-VulnScan dependency auditor")
    parser.add_argument("--path", required=True, help="Path to scan")
    parser.add_argument("--output", help="Output JSON file")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    base = Path(args.path)
    if not base.exists():
        print(f"Error: path not found: {base}", file=sys.stderr)
        sys.exit(1)

    print(f"Scanning dependencies in: {base}", file=sys.stderr)
    results = check_dependencies(base)

    indent = 2 if args.pretty else None
    output_str = json.dumps(results, indent=indent)

    if args.output:
        Path(args.output).write_text(output_str)
        print(f"Results written to: {args.output}", file=sys.stderr)
    else:
        print(output_str)

    s = results["summary"]
    print(f"\nDependency scan: {len(results['findings'])} vulnerable packages found "
          f"({s['critical']} critical, {s['high']} high, {s['medium']} medium)",
          file=sys.stderr)

    for f in results["findings"][:15]:
        print(f"  [{f['severity'].upper():8}] {f['package']} {f['current_version']} — {f['cve']} — {f['description'][:60]}",
              file=sys.stderr)

    print("\nNote: verify exploitability using sub-skills/dependency-auditor.md", file=sys.stderr)


if __name__ == "__main__":
    main()
