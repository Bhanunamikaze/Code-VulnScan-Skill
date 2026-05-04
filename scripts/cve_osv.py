#!/usr/bin/env python3
"""
Live CVE lookup via api.osv.dev.

Privacy note: package names and versions are sent to api.osv.dev.
Use --offline flag or set VULNSCAN_OFFLINE=1 to skip live queries.

Usage:
  python3 scripts/cve_osv.py --package django --version 4.0.0 --ecosystem PyPI
"""

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

OSV_API_URL = "https://api.osv.dev/v1/query"
CACHE_TTL_SECONDS = 86400  # 24 hours
_WORKSPACE_DIR = Path(__file__).parent.parent / "workspace"


def _cache_path(package: str, version: str, ecosystem: str) -> Path:
    key = hashlib.sha256(f"{ecosystem}:{package}:{version}".encode()).hexdigest()[:16]
    return _WORKSPACE_DIR / ".osv_cache" / ecosystem / f"{key}.json"


def _is_offline() -> bool:
    return os.environ.get("VULNSCAN_OFFLINE", "0") == "1"


def query_osv(package: str, version: str, ecosystem: str, offline: bool = False) -> list:
    """Query OSV.dev for vulnerabilities. Returns list of finding dicts."""
    if offline or _is_offline():
        return []

    cache = _cache_path(package, version, ecosystem)
    if cache.exists():
        age = time.time() - cache.stat().st_mtime
        if age < CACHE_TTL_SECONDS:
            try:
                return json.loads(cache.read_text()).get("vulns", [])
            except (json.JSONDecodeError, KeyError):
                pass

    payload = json.dumps({
        "package": {"name": package, "ecosystem": ecosystem},
        "version": version,
    }).encode()

    try:
        req = urllib.request.Request(
            OSV_API_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
    except (urllib.error.URLError, OSError, json.JSONDecodeError):
        return []

    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps(data))

    return data.get("vulns", [])


def osv_vulns_to_findings(vulns: list, package: str, version: str, file_path: str) -> list:
    """Convert OSV vuln list to scanner finding format."""
    findings = []
    for v in vulns:
        cve = next((alias for alias in v.get("aliases", []) if alias.startswith("CVE-")), v.get("id", "UNKNOWN"))
        severity_map = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5}
        cvss = severity_map.get(v.get("database_specific", {}).get("severity", ""), 5.0)
        findings.append({
            "vuln_type": "dependency_cve",
            "severity": "critical" if cvss >= 9.0 else "high" if cvss >= 7.0 else "medium",
            "cve": cve,
            "package": package,
            "version": version,
            "description": v.get("summary", v.get("details", "")[:200]),
            "cvss": cvss,
            "file_path": file_path,
            "source": "osv.dev",
        })
    return findings


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--ecosystem", default="PyPI")
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()

    vulns = query_osv(args.package, args.version, args.ecosystem, offline=args.offline)
    findings = osv_vulns_to_findings(vulns, args.package, args.version, "cli")
    print(json.dumps(findings, indent=2))


if __name__ == "__main__":
    main()
