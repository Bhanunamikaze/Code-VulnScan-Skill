#!/usr/bin/env python3
"""
Refresh the hardcoded KNOWN_VULNS list from OSV.dev.

Usage:
  python3 scripts/refresh_cve_db.py --ecosystem PyPI [--top 50]

Queries OSV.dev for the most critical recent CVEs and prints a Python dict
snippet that can replace the KNOWN_VULNS section in dependency.py.
"""
import json
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

# Top packages to check per ecosystem
TOP_PACKAGES = {
    "PyPI": [
        "django", "flask", "fastapi", "requests", "pillow", "cryptography",
        "pyyaml", "jinja2", "werkzeug", "sqlalchemy", "celery", "tornado",
        "aiohttp", "paramiko", "lxml", "urllib3", "starlette", "gunicorn",
        "reportlab", "langchain", "httpx", "redis", "pymongo", "numpy",
        "pandas", "transformers", "gradio", "mlflow", "setuptools", "oauthlib",
    ],
    "npm": [
        "lodash", "axios", "express", "jsonwebtoken", "node-fetch", "vm2",
        "semver", "tough-cookie", "next", "tar", "minimatch", "moment",
        "webpack", "babel", "react", "angular", "vue", "socket.io",
    ],
    "Maven": [
        "log4j-core", "spring-core", "spring-security-core", "jackson-databind",
        "struts2-core", "netty-handler", "commons-text", "guava",
    ],
}

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_VULNS_URL = "https://api.osv.dev/v1/vulns/"


def query_package(package: str, ecosystem: str) -> list:
    """Get all known vulns for a package (any version)."""
    payload = json.dumps({"package": {"name": package, "ecosystem": ecosystem}}).encode()
    try:
        req = urllib.request.Request(OSV_QUERY_URL, data=payload,
                                      headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read())
            return data.get("vulns", [])
    except Exception as e:
        print(f"  [WARN] {ecosystem}/{package}: {e}", file=sys.stderr)
        return []


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--ecosystem", choices=list(TOP_PACKAGES.keys()), default="PyPI")
    parser.add_argument("--top", type=int, default=30)
    args = parser.parse_args()

    ecosystem = args.ecosystem
    packages = TOP_PACKAGES[ecosystem][:args.top]

    results = {}
    for pkg in packages:
        print(f"Querying {ecosystem}/{pkg}...", file=sys.stderr)
        vulns = query_package(pkg, ecosystem)
        if vulns:
            results[pkg] = vulns
        time.sleep(0.2)  # be nice to the API

    # Print summary
    print(f"\n# Found {sum(len(v) for v in results.values())} CVEs across {len(results)} packages")
    for pkg, vulns in results.items():
        for v in vulns:
            cve = next((a for a in v.get("aliases", []) if a.startswith("CVE-")), v.get("id"))
            print(f"# {pkg}: {cve} — {v.get('summary', '')[:80]}")


if __name__ == "__main__":
    main()
