#!/usr/bin/env python3
"""
Dependency vulnerability checker — scans manifests for known-vulnerable versions.

Usage:
  python3 scripts/dependency.py --path <dir> [--output <file>] [--online]

Checks: requirements.txt, Pipfile, pyproject.toml, package.json, pom.xml,
        build.gradle, build.gradle.kts, go.mod, Gemfile.lock, composer.json,
        Cargo.lock, Cargo.toml, .csproj, packages.config, package-lock.json,
        yarn.lock, pnpm-lock.yaml, poetry.lock, Pipfile.lock, composer.lock,
        go.sum
"""

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from scripts.utils.languages import get_manifest_files

# KNOWN_VULNS — last refreshed 2025-01-15 — run scripts/refresh_cve_db.py to update
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
        ("tornado", "<6.3.3", ">=6.3.3", "CVE-2023-28370", 6.1, "open_redirect", "Open redirect in StaticFileHandler via crafted URL"),
        ("starlette", "<0.36.2", ">=0.36.2", "CVE-2024-24762", 7.5, "dos", "Multipart form parsing DoS via infinite loop"),
        ("gunicorn", "<21.2.0", ">=21.2.0", "CVE-2024-1135", 7.5, "http_smuggling", "HTTP request smuggling via Transfer-Encoding header"),
        ("reportlab", "<3.6.13", ">=4.0.0", "CVE-2023-33733", 9.8, "rce", "Arbitrary code execution via malicious HTML in PDF generation"),
        ("setuptools", "<65.5.1", ">=65.5.1", "CVE-2022-40897", 5.9, "dos", "ReDoS in package_index URL parsing"),
        ("langchain", "<0.0.341", ">=0.0.341", "CVE-2023-46229", 9.8, "rce", "Arbitrary code execution via LLMChain eval injection"),
        ("httpx", "<0.23.0", ">=0.23.0", "CVE-2021-41945", 8.1, "ssrf", "SSRF via URL redirect with encoded host"),
        ("redis", "<4.5.4", ">=4.5.4", "CVE-2023-28859", 6.5, "ssrf", "SSRF via unvalidated Redis connection URL"),
        ("pymongo", "<4.6.2", ">=4.6.2", "CVE-2024-5629", 7.5, "dos", "Out-of-bounds read in BSON decoding"),
        ("django", "<4.2.0", ">=4.2.0", "CVE-2023-43665", 7.5, "dos", "ReDoS in EmailValidator and URLValidator"),
        ("django", "<4.1.3", ">=4.1.3", "CVE-2022-41323", 7.5, "dos", "Potential ReDoS in internationalized URLs"),
        ("numpy", "<1.22.0", ">=1.22.0", "CVE-2021-41495", 6.5, "dos", "NULL pointer dereference in numpy"),
        ("transformers", "<4.30.0", ">=4.30.0", "CVE-2023-48022", 9.8, "rce", "Arbitrary code execution via pickle in transformers"),
        ("gradio", "<3.34.0", ">=3.34.0", "CVE-2023-34239", 9.8, "rce", "Path traversal and arbitrary code execution"),
        ("fastapi", "<0.109.1", ">=0.109.1", "CVE-2024-24762", 7.5, "dos", "ReDoS via form parsing"),
        ("httpx", "<0.27.0", ">=0.27.0", "CVE-2024-35195", 5.9, "ssrf", "Unintended credential exposure in redirects"),
        ("ecdsa", "<0.18.0", ">=0.18.0", "CVE-2024-23342", 7.4, "timing_attack", "Minerva timing side-channel in ECDSA"),
        ("oauthlib", "<3.2.2", ">=3.2.2", "CVE-2022-36087", 6.5, "dos", "ReDoS in URI validation"),
        ("pyarrow", "<14.0.1", ">=14.0.1", "CVE-2023-47248", 9.8, "rce", "Arbitrary code execution via pickle in IPC"),
        ("mlflow", "<2.9.2", ">=2.9.2", "CVE-2024-27132", 9.8, "path_traversal", "Path traversal in model loading"),
        ("pytorch", "<2.1.2", ">=2.1.2", "CVE-2024-31580", 9.8, "rce", "Code execution via torch.load without weights_only=True"),
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
        ("xml2js", "<0.5.0", ">=0.5.0", "CVE-2023-0842", 7.5, "prototype_pollution", "Prototype pollution via __proto__ key in parsed XML"),
        ("cross-spawn", "<7.0.5", ">=7.0.5", "CVE-2024-21538", 7.5, "redos", "ReDoS via specially crafted shell argument string"),
        ("ua-parser-js", "<1.0.33", ">=1.0.33", "CVE-2022-25927", 7.5, "redos", "ReDoS via malformed User-Agent string"),
        ("protobufjs", "<7.2.4", ">=7.2.4", "CVE-2023-36665", 9.8, "prototype_pollution", "Prototype pollution in MessageFactory.fromObject"),
        ("tar", "<6.2.1", ">=6.2.1", "CVE-2024-28863", 6.5, "dos", "DoS via recursive symlink in tar archive"),
        ("passport", "<0.6.0", ">=0.6.0", "CVE-2022-25896", 7.4, "session_fixation", "Session fixation via lack of session regeneration on login"),
        ("ip", "<2.0.1", ">=2.0.1", "CVE-2024-29415", 8.1, "ssrf", "Private IP check bypass via ::ffff:127.0.0.1 notation"),
        ("jose", "<4.15.5", ">=4.15.5", "CVE-2024-28176", 7.5, "dos", "DoS via PBKDF2 large iteration count in JWE decrypt"),
        ("jsonwebtoken", "<9.0.0", ">=9.0.0", "CVE-2022-23541", 8.8, "auth_bypass", "Authentication bypass via algorithm confusion (RS256 vs HS256)"),
    ],
    "npm": [
        ("lodash", "<4.17.21", ">=4.17.21", "CVE-2021-23337", 7.2, "cmdi", "Command injection via template"),
        ("lodash", "<4.17.21", ">=4.17.21", "CVE-2020-8203", 7.4, "proto_pollution", "Prototype pollution via zipObjectDeep"),
        ("axios", "<0.21.2", ">=0.21.2", "CVE-2021-3749", 7.5, "dos", "Regular expression DoS in axios"),
        ("axios", "<1.6.0", ">=1.6.0", "CVE-2023-45857", 6.5, "ssrf", "SSRF via XSRF-TOKEN header leak"),
        ("express", "<4.19.2", ">=4.19.2", "CVE-2024-29041", 6.1, "open_redirect", "Open redirect in res.location()"),
        ("jsonwebtoken", "<9.0.0", ">=9.0.0", "CVE-2022-23529", 9.8, "auth_bypass", "Remote code execution via malicious JWK"),
        ("node-fetch", "<2.6.7", ">=2.6.7", "CVE-2022-0235", 6.1, "ssrf", "Exposure of sensitive information via redirect"),
        ("vm2", "<3.9.19", ">=3.9.19", "CVE-2023-29017", 10.0, "sandbox_escape", "Sandbox escape via exception handling"),
        ("semver", "<7.5.2", ">=7.5.2", "CVE-2022-25883", 7.5, "dos", "ReDoS in semver.satisfies()"),
        ("tough-cookie", "<4.1.3", ">=4.1.3", "CVE-2023-26136", 6.5, "proto_pollution", "Prototype pollution via psl.get"),
        ("next", "<14.1.1", ">=14.1.1", "CVE-2024-34351", 7.5, "ssrf", "SSRF in Server Actions"),
        ("next", "<13.5.1", ">=13.5.1", "CVE-2023-46298", 7.5, "dos", "DoS via malformed HTTP request"),
        ("tar", "<6.1.9", ">=6.1.9", "CVE-2021-37701", 8.6, "path_traversal", "Path traversal via relative path extraction"),
        ("minimatch", "<3.0.5", ">=3.0.5", "CVE-2022-3517", 7.5, "dos", "ReDoS in minimatch"),
        ("moment", "<2.29.4", ">=2.29.4", "CVE-2022-24785", 7.5, "path_traversal", "Path traversal in moment.locale()"),
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
        ("struts2-core", "<6.3.0", ">=6.3.0", "CVE-2023-50164", 9.8, "rce", "File upload path traversal leads to RCE via partial path-traversal attack"),
        ("spring-framework", "<5.3.31|<6.0.14", ">=6.0.14", "CVE-2023-20861", 6.5, "dos", "SpEL expression DoS via crafted expression in annotation"),
        ("tomcat-embed-core", "<10.1.16|<9.0.83|<8.5.96", ">=10.1.16", "CVE-2023-46589", 7.5, "http_smuggling", "HTTP request smuggling via invalid Transfer-Encoding header"),
        ("guava", "<32.0.0-jre", ">=32.0.0-jre", "CVE-2023-2976", 7.1, "path_traversal", "Predictable temp directory allows symlink race in Files.createTempDir()"),
        ("okhttp", "<4.12.0", ">=4.12.0", "CVE-2023-3635", 7.5, "dos", "GzipSource DoS via malformed Content-Encoding"),
        ("netty-all", "<4.1.100.Final", ">=4.1.100.Final", "CVE-2023-44487", 7.5, "dos", "HTTP/2 rapid reset attack amplification"),
        ("logback-core", "<1.4.12|<1.3.12", ">=1.4.12", "CVE-2023-6378", 9.8, "rce", "Deserialization of untrusted data via specially crafted receiver component"),
    ],
    "maven": [
        ("log4j-core", "<2.17.1", ">=2.17.1", "CVE-2021-44228", 10.0, "rce", "Log4Shell: JNDI injection"),
        ("log4j-core", "<2.17.1", ">=2.17.1", "CVE-2021-45105", 7.5, "dos", "Log4j2 DoS via recursive lookup"),
        ("spring-core", "<5.3.26", ">=5.3.26", "CVE-2022-22965", 9.8, "rce", "Spring4Shell: RCE via data binding"),
        ("spring-security-core", "<5.8.3", ">=5.8.3", "CVE-2023-20862", 7.5, "auth_bypass", "Authentication bypass in Spring Security"),
        ("jackson-databind", "<2.13.4", ">=2.13.4", "CVE-2022-42003", 7.5, "dos", "Deeply nested arrays cause StackOverflow"),
        ("struts2-core", "<2.5.33", ">=2.5.33", "CVE-2023-50164", 9.8, "rce", "File upload path traversal leading to RCE"),
        ("netty-handler", "<4.1.86", ">=4.1.86", "CVE-2023-34462", 6.5, "dos", "SniHandler DoS via memory exhaustion"),
        ("commons-text", "<1.10.0", ">=1.10.0", "CVE-2022-42889", 9.8, "rce", "Text4Shell: interpolation injection"),
        ("guava", "<32.0.0", ">=32.0.0", "CVE-2023-2976", 7.1, "path_traversal", "Path traversal in Guava's Files.createTempDir"),
    ],
    "go": [
        ("golang.org/x/net", "<0.17.0", ">=0.17.0", "CVE-2023-44487", 7.5, "dos", "HTTP/2 rapid reset attack DoS"),
        ("golang.org/x/crypto", "<0.13.0", ">=0.13.0", "CVE-2023-48795", 5.9, "mitm", "Terrapin SSH downgrade attack"),
        ("github.com/gin-gonic/gin", "<1.9.1", ">=1.9.1", "CVE-2023-29401", 4.3, "dos", "Large multipart form DoS"),
        ("github.com/dgrijalva/jwt-go", "<4.0.0", ">=4.0.0", "CVE-2020-26160", 7.5, "auth_bypass", "Audience claim check bypass allows token forgery when aud is a string not array"),
        ("google.golang.org/grpc", "<1.57.1", ">=1.57.1", "CVE-2023-44487", 7.5, "dos", "HTTP/2 rapid reset DDoS amplification attack"),
        ("golang.org/x/text", "<0.3.8", ">=0.3.8", "CVE-2022-32149", 7.5, "dos", "Panic via crafted Accept-Language header in language tag parsing"),
        ("github.com/go-jose/go-jose/v3", "<3.0.1", ">=3.0.1", "CVE-2023-26483", 7.5, "dos", "ECDH-ES with invalid public key causes DoS in JWE decryption"),
        ("golang.org/x/net", "<0.23.0", ">=0.23.0", "CVE-2024-45338", 7.5, "dos", "HTTP/2 CONTINUATION flood causes server DoS"),
    ],
    "ruby": [
        ("rails", "<7.0.8|<7.1.1", ">=7.1.1", "CVE-2023-38037", 5.4, "info_disclosure", "Information disclosure via ReDoS"),
        ("nokogiri", "<1.15.4", ">=1.15.4", "CVE-2023-45648", 5.3, "xxe", "XML namespace confusion"),
        ("devise", "<4.9.3", ">=4.9.3", "CVE-2019-5421", 7.5, "timing_attack", "Timing attack on password reset"),
        ("rack", "<2.2.8", ">=2.2.8", "CVE-2023-27539", 7.5, "dos", "ReDoS in header parsing"),
        ("activerecord", "<7.0.8|<7.1.1", ">=7.1.1", "CVE-2023-22795", 7.5, "dos", "ReDoS via crafted SQL string parameter in query method"),
        ("omniauth", "<2.1.2", ">=2.1.2", "CVE-2021-41136", 3.7, "timing_attack", "Timing attack via inconsistent request phase handling"),
        ("activesupport", "<7.0.8", ">=7.0.8", "CVE-2023-28362", 6.1, "xss", "XSS via ANSI character injection in log output rendered in browser"),
        ("carrierwave", "<1.3.4|<2.2.6", ">=2.2.6", "CVE-2023-49090", 7.5, "xxe", "SVG upload XXE allows file read via crafted SVG content"),
    ],
    "php": [
        ("laravel/framework", "<10.28.0", ">=10.28.0", "CVE-2023-43814", 6.5, "info_disclosure", "Debug mode info leak"),
        ("guzzlehttp/guzzle", "<7.5.0", ">=7.5.0", "CVE-2022-31090", 7.5, "ssrf", "SSRF via URL parsing"),
        ("symfony/http-foundation", "<6.3.1", ">=6.3.1", "CVE-2023-25575", 7.5, "dos", "ReDoS in header parsing"),
        ("phpoffice/phpspreadsheet", "<1.29.0", ">=1.29.0", "CVE-2024-25118", 8.8, "xxe", "XXE via XLSX files"),
        ("guzzlehttp/psr7", "<1.9.1|<2.4.5", ">=2.4.5", "CVE-2023-29197", 7.5, "header_injection", "Header injection via CRLF in URI values passed to PSR-7 methods"),
        ("symfony/http-kernel", "<6.3.5|<5.4.33", ">=6.3.5", "CVE-2023-46734", 6.1, "xss", "XSS via Content-Security-Policy nonce bypass in error pages"),
        ("nesbot/carbon", "<2.72.3", ">=2.72.3", "CVE-2023-42282", 7.5, "redos", "ReDoS via crafted date string in Carbon parse()"),
        ("phpseclib/phpseclib", "<3.0.19", ">=3.0.19", "CVE-2023-27560", 7.5, "dos", "Infinite loop in BER-encoded length decoding"),
    ],
    "rust": [
        ("openssl", "<0.10.55", ">=0.10.55", "CVE-2023-0286", 7.4, "dos", "X.400 GeneralName OOB read"),
        ("h2", "<0.3.17", ">=0.3.17", "CVE-2023-26964", 7.5, "dos", "HTTP/2 header resource exhaustion"),
        ("rustls", "<0.20.9|<0.21.7", ">=0.21.7", "CVE-2023-36619", 7.5, "tls", "Incorrect TLS handshake handling"),
        ("hyper", "<0.14.27", ">=0.14.27", "CVE-2023-44487", 7.5, "dos", "HTTP/2 rapid reset attack"),
        ("tokio", "<1.29.1", ">=1.29.1", "CVE-2023-22466", 5.3, "dos", "Thread count manipulation"),
        ("regex", "<1.5.5", ">=1.5.5", "CVE-2022-24713", 7.5, "dos", "ReDoS via specially crafted regex pattern causes stack overflow"),
        ("tar", "<0.4.38", ">=0.4.38", "CVE-2021-38193", 7.5, "path_traversal", "Path traversal during tar archive extraction via crafted path"),
        ("prost", "<0.12.0", ">=0.12.0", "CVE-2024-27308", 7.5, "dos", "DoS via crafted protobuf message exceeding recursive depth limit"),
    ],
    "dotnet": [
        ("Microsoft.AspNetCore.App", "<7.0.14|<8.0.0", ">=8.0.0", "CVE-2023-44487", 7.5, "dos", "HTTP/2 rapid reset attack"),
        ("System.Text.Json", "<7.0.4", ">=8.0.0", "CVE-2023-21173", 7.5, "dos", "DoS via large JSON"),
        ("Microsoft.Data.SqlClient", "<5.1.2", ">=5.1.2", "CVE-2024-0056", 8.7, "mitm", "SQL connection string injection"),
        ("Newtonsoft.Json", "<13.0.1", ">=13.0.3", "CVE-2024-21907", 7.5, "dos", "DoS via deep nesting ReDoS"),
        ("Microsoft.AspNetCore.Authentication.JwtBearer", "<8.0.0", ">=8.0.0", "CVE-2024-21319", 6.8, "auth_bypass", "Insufficient JWT audience validation allows cross-tenant token acceptance"),
        ("Microsoft.Identity.Client", "<4.60.1", ">=4.60.1", "CVE-2024-26186", 7.5, "auth_bypass", "MSAL token cache poisoning via crafted authority URI"),
        ("IdentityServer4", "<4.1.2", ">=4.1.2", "CVE-2022-23108", 8.1, "auth_bypass", "Authentication bypass via client_secret_jwt algorithm confusion"),
        ("Npgsql", "<8.0.1", ">=8.0.1", "CVE-2024-0057", 7.5, "mitm", "Improper TLS certificate validation allows MITM on PostgreSQL connections"),
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


def parse_cargo_toml(path: Path) -> list:
    """Parse Cargo.toml [dependencies] and [dev-dependencies] sections."""
    deps = []
    content = path.read_text(errors="replace")
    in_deps = False
    section = ""
    for line in content.splitlines():
        line_s = line.strip()
        if re.match(r'^\[(dev-dependencies|build-dependencies|dependencies)\]', line_s):
            in_deps = True
            section = line_s
            continue
        if line_s.startswith("[") and in_deps:
            in_deps = False
            continue
        if not in_deps:
            continue
        # name = "1.2.3"  or  name = { version = "1.2.3" }
        m = re.match(r'^([\w\-]+)\s*=\s*["\']([^"\']+)["\']', line_s)
        if m:
            deps.append({"name": m.group(1).lower(), "version": re.sub(r"[^0-9.]", "", m.group(2)), "source": str(path)})
            continue
        m = re.match(r'^([\w\-]+)\s*=\s*\{[^}]*version\s*=\s*["\']([^"\']+)["\']', line_s)
        if m:
            deps.append({"name": m.group(1).lower(), "version": re.sub(r"[^0-9.]", "", m.group(2)), "source": str(path)})
    return [d for d in deps if d["version"]]


def parse_csproj(path: Path) -> list:
    """Parse .csproj PackageReference elements."""
    content = path.read_text(errors="replace")
    deps = []
    for m in re.finditer(
        r'<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"',
        content, re.IGNORECASE
    ):
        ver = re.sub(r"[^0-9.]", "", m.group(2))
        if ver:
            deps.append({"name": m.group(1).lower(), "version": ver, "source": str(path)})
    # Also handle multi-line form
    for m in re.finditer(
        r'<PackageReference\s+Include="([^"]+)"[^>]*>.*?<Version>([^<]+)</Version>',
        content, re.IGNORECASE | re.DOTALL
    ):
        ver = re.sub(r"[^0-9.]", "", m.group(2).strip())
        if ver:
            deps.append({"name": m.group(1).lower(), "version": ver, "source": str(path)})
    return deps


def parse_packages_config(path: Path) -> list:
    """Parse packages.config (NuGet legacy format)."""
    content = path.read_text(errors="replace")
    deps = []
    for m in re.finditer(r'<package\s+id="([^"]+)"\s+version="([^"]+)"', content, re.IGNORECASE):
        ver = re.sub(r"[^0-9.]", "", m.group(2))
        if ver:
            deps.append({"name": m.group(1).lower(), "version": ver, "source": str(path)})
    return deps


def parse_build_gradle(path: Path) -> list:
    """Parse build.gradle / build.gradle.kts dependency blocks."""
    content = path.read_text(errors="replace")
    deps = []
    # Groovy: implementation 'group:artifact:version' or "group:artifact:version"
    for m in re.finditer(r"""(?:implementation|api|compile|testImplementation|runtimeOnly)\s+['"]([^'"]+):([^'"]+):([^'"]+)['"]""", content):
        ver = re.sub(r"[^0-9.]", "", m.group(3))
        if ver:
            deps.append({"name": m.group(2).lower(), "version": ver, "source": str(path)})
    # Kotlin DSL: implementation("group:artifact:version")
    for m in re.finditer(r"""(?:implementation|api|testImplementation)\s*\(\s*["']([^"']+):([^"']+):([^"']+)["']\s*\)""", content):
        ver = re.sub(r"[^0-9.]", "", m.group(3))
        if ver:
            deps.append({"name": m.group(2).lower(), "version": ver, "source": str(path)})
    return deps


def parse_pyproject_toml(path: Path) -> list:
    """Parse pyproject.toml [project.dependencies] and [tool.poetry.dependencies]."""
    content = path.read_text(errors="replace")
    deps = []
    in_section = False
    for line in content.splitlines():
        line_s = line.strip()
        if re.match(r'^\[project\.dependencies\]|\[tool\.poetry\.dependencies\]', line_s):
            in_section = True
            continue
        if line_s.startswith("[") and in_section:
            in_section = False
            continue
        if not in_section:
            # Also parse PEP 508 inline list: dependencies = ["requests>=2.0", ...]
            m = re.search(r'"([\w\-\.]+)\s*(?:>=|==|~=|<=|!=|>|<)\s*([\d\.]+)', line_s)
            if m:
                deps.append({"name": m.group(1).lower(), "version": m.group(2), "source": str(path)})
            continue
        # name = ">=1.2.3"  (poetry format)
        m = re.match(r'^([\w\-\.]+)\s*=\s*["\'](?:[\^~>=<]*)([\d\.]+)', line_s)
        if m:
            deps.append({"name": m.group(1).lower(), "version": m.group(2), "source": str(path)})
    return [d for d in deps if d["version"]]


def parse_package_lock_json(path: Path) -> list:
    """Parse package-lock.json (npm v1/v2/v3 lockfile)."""
    try:
        data = json.loads(path.read_text(errors="replace"))
    except (json.JSONDecodeError, OSError):
        return []
    deps = []
    # v2/v3 format uses "packages" key
    if "packages" in data:
        for pkg_path, pkg_data in data["packages"].items():
            if pkg_path == "":
                continue  # skip root
            # Strip leading "node_modules/" to get name
            name = pkg_path
            if name.startswith("node_modules/"):
                name = name[len("node_modules/"):]
            version = pkg_data.get("version", "")
            if not version:
                continue
            # is_direct: no nested node_modules after stripping the leading one
            is_direct = "/" not in name.lstrip("@").split("/", 1)[-1] if name.startswith("@") else "/" not in name
            deps.append({
                "name": name.lower(),
                "version": version,
                "ecosystem": "npm",
                "is_direct": is_direct,
                "source": str(path),
            })
    elif "dependencies" in data:
        # v1 format
        for pkg_name, pkg_data in data["dependencies"].items():
            if "resolved" not in pkg_data:
                continue
            version = pkg_data.get("version", "")
            if not version:
                continue
            deps.append({
                "name": pkg_name.lower(),
                "version": version,
                "ecosystem": "npm",
                "is_direct": True,
                "source": str(path),
            })
    return deps


def parse_yarn_lock(path: Path) -> list:
    """Parse yarn.lock (Yarn v1 format)."""
    deps = []
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return []
    pkg_name = None
    name_pattern = re.compile(r'^"?([a-zA-Z0-9@._/\-]+)@[^:]+:?\s*$')
    version_pattern = re.compile(r'^\s{2}version\s+"([^"]+)"')
    for line in lines:
        m = name_pattern.match(line)
        if m and not line.startswith(" ") and not line.startswith("#"):
            pkg_name = m.group(1)
            continue
        if pkg_name:
            vm = version_pattern.match(line)
            if vm:
                deps.append({
                    "name": pkg_name.lower(),
                    "version": vm.group(1),
                    "ecosystem": "npm",
                    "is_direct": False,
                    "source": str(path),
                })
                pkg_name = None
    return deps


def parse_pnpm_lock(path: Path) -> list:
    """Parse pnpm-lock.yaml (simplified text-based parsing)."""
    deps = []
    try:
        content = path.read_text(errors="replace")
    except OSError:
        return []
    pattern = re.compile(r'^\s{2}/([a-zA-Z0-9@._/\-]+)[@/]([0-9][^:]+):')
    for line in content.splitlines():
        m = pattern.match(line)
        if m:
            deps.append({
                "name": m.group(1).lower(),
                "version": m.group(2).strip(),
                "ecosystem": "npm",
                "is_direct": False,
                "source": str(path),
            })
    return deps


def parse_poetry_lock(path: Path) -> list:
    """Parse poetry.lock (TOML [[package]] blocks via regex)."""
    deps = []
    try:
        content = path.read_text(errors="replace")
    except OSError:
        return []
    # Split on [[package]] blocks
    blocks = re.split(r'\[\[package\]\]', content)
    for block in blocks[1:]:  # skip leading content before first [[package]]
        name_m = re.search(r'^name\s*=\s*"([^"]+)"', block, re.MULTILINE)
        ver_m = re.search(r'^version\s*=\s*"([^"]+)"', block, re.MULTILINE)
        if name_m and ver_m:
            deps.append({
                "name": name_m.group(1).lower(),
                "version": ver_m.group(1),
                "ecosystem": "pypi",
                "is_direct": False,
                "source": str(path),
            })
    return deps


def parse_pipfile_lock(path: Path) -> list:
    """Parse Pipfile.lock (JSON format)."""
    try:
        data = json.loads(path.read_text(errors="replace"))
    except (json.JSONDecodeError, OSError):
        return []
    deps = []
    for section, is_direct in (("default", True), ("develop", False)):
        for pkg_name, pkg_data in data.get(section, {}).items():
            version = pkg_data.get("version", "")
            # Strip leading == from version specifier
            version = version.lstrip("=")
            if version:
                deps.append({
                    "name": pkg_name.lower(),
                    "version": version,
                    "ecosystem": "pypi",
                    "is_direct": is_direct,
                    "source": str(path),
                })
    return deps


def parse_composer_lock(path: Path) -> list:
    """Parse composer.lock (JSON format)."""
    try:
        data = json.loads(path.read_text(errors="replace"))
    except (json.JSONDecodeError, OSError):
        return []
    deps = []
    for section, is_direct in (("packages", True), ("packages-dev", False)):
        for pkg in data.get(section, []):
            name = pkg.get("name", "")
            version = pkg.get("version", "")
            # Strip leading 'v' from version if present
            version = version.lstrip("v")
            if name and version:
                deps.append({
                    "name": name.lower(),
                    "version": version,
                    "ecosystem": "packagist",
                    "is_direct": is_direct,
                    "source": str(path),
                })
    return deps


def parse_cargo_lock(path: Path) -> list:
    """Parse Cargo.lock (TOML [[package]] blocks via regex)."""
    deps = []
    try:
        content = path.read_text(errors="replace")
    except OSError:
        return []
    blocks = re.split(r'\[\[package\]\]', content)
    for block in blocks[1:]:
        name_m = re.search(r'^name\s*=\s*"([^"]+)"', block, re.MULTILINE)
        ver_m = re.search(r'^version\s*=\s*"([^"]+)"', block, re.MULTILINE)
        if name_m and ver_m:
            deps.append({
                "name": name_m.group(1).lower(),
                "version": ver_m.group(1),
                "ecosystem": "crates.io",
                "is_direct": False,
                "source": str(path),
            })
    return deps


def parse_go_sum(path: Path) -> list:
    """Parse go.sum (deduplicated by module name)."""
    deps = {}
    try:
        content = path.read_text(errors="replace")
    except OSError:
        return []
    pattern = re.compile(r'^([^\s]+)\s+v([0-9][^\s]+)\s+')
    for line in content.splitlines():
        m = pattern.match(line)
        if m:
            module = m.group(1).lower()
            version = m.group(2)
            # Keep entry (dedup by module name — last wins, preserving latest)
            deps[module] = {
                "name": module,
                "version": version,
                "ecosystem": "go",
                "is_direct": False,
                "source": str(path),
            }
    return list(deps.values())


PARSERS = {
    "requirements.txt": ("python", parse_requirements_txt),
    "requirements-dev.txt": ("python", parse_requirements_txt),
    "requirements-prod.txt": ("python", parse_requirements_txt),
    "pyproject.toml": ("python", parse_pyproject_toml),
    "package.json": ("javascript", parse_package_json),
    "pom.xml": ("java", parse_pom_xml),
    "build.gradle": ("java", parse_build_gradle),
    "build.gradle.kts": ("java", parse_build_gradle),
    "go.mod": ("go", parse_go_mod),
    "gemfile.lock": ("ruby", parse_gemfile_lock),
    "composer.json": ("php", parse_composer_json),
    "cargo.toml": ("rust", parse_cargo_toml),
    "packages.config": ("dotnet", parse_packages_config),
    # Lockfile parsers (Task 4.1)
    "package-lock.json": ("npm", parse_package_lock_json),
    "yarn.lock": ("npm", parse_yarn_lock),
    "pnpm-lock.yaml": ("npm", parse_pnpm_lock),
    "poetry.lock": ("pypi", parse_poetry_lock),
    "pipfile.lock": ("pypi", parse_pipfile_lock),
    "composer.lock": ("packagist", parse_composer_lock),
    "cargo.lock": ("crates.io", parse_cargo_lock),
    "go.sum": ("go", parse_go_sum),
}


def check_dependencies(base_path: Path, online: bool = False) -> dict:
    all_findings = []
    all_deps = []
    manifests_found = []

    manifests = get_manifest_files(base_path)
    for manifest in manifests:
        name_lower = manifest.name.lower()
        # Handle variable-name manifests (.csproj)
        if name_lower.endswith(".csproj"):
            ecosystem, parser = "dotnet", parse_csproj
        elif name_lower not in PARSERS:
            continue
        else:
            ecosystem, parser = PARSERS[name_lower]
        deps = parser(manifest)
        manifests_found.append({"file": str(manifest.relative_to(base_path)), "ecosystem": ecosystem, "deps": len(deps)})
        all_deps.extend([(ecosystem, d) for d in deps])

    # Track CVEs already found via KNOWN_VULNS to avoid duplicates from OSV
    seen_cves: set = set()

    for ecosystem, dep in all_deps:
        pkg_name = dep["name"]
        version = dep["version"]
        vulns = KNOWN_VULNS.get(ecosystem, [])
        for pkg, vuln_range, safe_ver, cve, cvss, vuln_type, description in vulns:
            if pkg.lower() == pkg_name and version_in_range(version, vuln_range):
                seen_cves.add(f"{pkg_name}:{cve}")
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
                    "source": "known_vulns",
                })

    # Live OSV.dev lookup (Task 4.2) — gated behind online flag
    if online:
        try:
            from scripts.cve_osv import query_osv, osv_vulns_to_findings
            # Ecosystem name mapping from internal names to OSV ecosystem names
            osv_ecosystem_map = {
                "python": "PyPI",
                "pypi": "PyPI",
                "javascript": "npm",
                "npm": "npm",
                "java": "Maven",
                "maven": "Maven",
                "go": "Go",
                "ruby": "RubyGems",
                "php": "Packagist",
                "packagist": "Packagist",
                "rust": "crates.io",
                "crates.io": "crates.io",
                "dotnet": "NuGet",
            }
            for ecosystem, dep in all_deps:
                pkg_name = dep["name"]
                version = dep["version"]
                osv_eco = osv_ecosystem_map.get(ecosystem, ecosystem)
                osv_vulns = query_osv(pkg_name, version, osv_eco, offline=False)
                osv_findings = osv_vulns_to_findings(osv_vulns, pkg_name, version, dep.get("source", ""))
                for f in osv_findings:
                    dedup_key = f"{pkg_name}:{f['cve']}"
                    if dedup_key not in seen_cves:
                        seen_cves.add(dedup_key)
                        all_findings.append({
                            "package": pkg_name,
                            "ecosystem": ecosystem,
                            "current_version": version,
                            "vulnerable_range": "see OSV",
                            "safe_version": "see OSV",
                            "cve": f["cve"],
                            "cvss": f["cvss"],
                            "vuln_type": f["vuln_type"],
                            "description": f["description"],
                            "is_dev": dep.get("is_dev", False),
                            "manifest": dep.get("source", ""),
                            "severity": f["severity"],
                            "status": "candidate",
                            "source": "osv.dev",
                        })
        except ImportError:
            print("Warning: cve_osv module not available; skipping live OSV lookup.", file=sys.stderr)

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
    parser.add_argument("--online", action="store_true",
                        help="Query api.osv.dev for live CVE data (sends package names/versions)")
    args = parser.parse_args()

    base = Path(args.path)
    if not base.exists():
        print(f"Error: path not found: {base}", file=sys.stderr)
        sys.exit(1)

    print(f"Scanning dependencies in: {base}", file=sys.stderr)
    if args.online:
        print("Live OSV.dev lookup enabled (--online)", file=sys.stderr)
    results = check_dependencies(base, online=args.online)

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
