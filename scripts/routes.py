#!/usr/bin/env python3
"""
Route/endpoint extraction — identifies API routes and HTTP entry points.

Extracts routes from Flask, Django, FastAPI, Express, Spring, and generic patterns.
Results are stored in the scan DB and shown in reports.
"""
import re
import json
from pathlib import Path
from typing import Optional

# Per-framework route patterns
# Each entry: (pattern, method_group_index_or_None, path_group_index)
ROUTE_PATTERNS = {
    "flask": [
        (r"@(?:app|bp|blueprint)\s*\.\s*route\s*\(\s*['\"]([^'\"]+)['\"](?:[^)]*methods\s*=\s*\[([^\]]+)\])?", 1, 0),
        (r"@(?:app|bp)\s*\.\s*(get|post|put|delete|patch)\s*\(\s*['\"]([^'\"]+)['\"]", 0, 1),
    ],
    "fastapi": [
        (r"@(?:app|router)\s*\.\s*(get|post|put|delete|patch|options|head)\s*\(\s*['\"]([^'\"]+)['\"]", 0, 1),
    ],
    "django": [
        (r"path\s*\(\s*['\"]([^'\"]*)['\"]", None, 0),
        (r"re_path\s*\(\s*r?['\"]([^'\"]*)['\"]", None, 0),
        (r"url\s*\(\s*r?['\"]([^'\"]*)['\"]", None, 0),
    ],
    "express": [
        (r"(?:app|router)\s*\.\s*(get|post|put|delete|patch|use)\s*\(\s*['\"`]([^'\"` ]+)['\"`]", 0, 1),
    ],
    "spring": [
        (r"@(?:Get|Post|Put|Delete|Patch|Request)Mapping\s*(?:\(\s*(?:value\s*=\s*)?['\"]([^'\"]+)['\"])?", None, 0),
        (r'@RequestMapping\s*\(\s*["\']([^"\']+)["\']', None, 0),
    ],
    "gin": [
        (r'r\s*\.\s*(GET|POST|PUT|DELETE|PATCH)\s*\(\s*["\']([^"\']+)["\']', 0, 1),
        (r'router\s*\.\s*(GET|POST|PUT|DELETE|PATCH)\s*\(\s*["\']([^"\']+)["\']', 0, 1),
    ],
    "rails": [
        (r"(?:get|post|put|delete|patch|resources)\s+['\"]([^'\"]+)['\"]", None, 0),
        (r"match\s+['\"]([^'\"]+)['\"]", None, 0),
    ],
}

def extract_routes(content: str, file_path: str, framework: str = None) -> list:
    """Extract route definitions from a source file."""
    routes = []
    lines = content.splitlines()

    frameworks_to_try = [framework] if framework else list(ROUTE_PATTERNS.keys())

    for fw in frameworks_to_try:
        patterns = ROUTE_PATTERNS.get(fw, [])
        for pattern_tuple in patterns:
            pattern = pattern_tuple[0]
            method_idx = pattern_tuple[1]
            path_idx = pattern_tuple[2]

            for m in re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE):
                line_num = content[:m.start()].count('\n') + 1
                groups = m.groups()

                path = None
                method = None

                if method_idx is not None and method_idx < len(groups) and groups[method_idx]:
                    method = groups[method_idx].upper()
                if path_idx < len(groups) and groups[path_idx]:
                    path = groups[path_idx]

                if path is not None:
                    # Clean up the path
                    path = path.strip()
                    if not path.startswith('/') and not path.startswith('^') and not path.startswith('r\''):
                        path = '/' + path

                    routes.append({
                        "file_path": file_path,
                        "line": line_num,
                        "path": path,
                        "method": method or "ANY",
                        "framework": fw,
                        "code": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    })

    # Deduplicate
    seen = set()
    unique = []
    for r in routes:
        key = (r["file_path"], r["line"], r["path"])
        if key not in seen:
            seen.add(key)
            unique.append(r)

    return unique


def extract_routes_from_project(base_path: Path, files: list, frameworks: dict = None) -> list:
    """Scan all relevant files and extract routes."""
    all_routes = []
    route_file_patterns = [
        r"route", r"url", r"view", r"controller", r"handler", r"api",
    ]

    for f in files:
        fpath = Path(f["path"])
        lang = f.get("language", "")

        # Only process source files likely to have routes
        if lang not in ("python", "javascript", "typescript", "java", "go", "ruby", "php"):
            continue

        # Prioritize files with route-like names
        name_lower = fpath.name.lower()
        stem_lower = fpath.stem.lower()
        is_route_file = any(p in stem_lower or p in name_lower for p in route_file_patterns)

        try:
            content = fpath.read_text(errors="replace")
        except OSError:
            continue

        # Determine which framework to try based on detected frameworks
        fw = None
        if frameworks:
            for fw_name in ("flask", "fastapi", "django", "express", "spring", "gin", "rails"):
                if fw_name in frameworks:
                    fw = fw_name
                    break

        routes = extract_routes(content, str(fpath), fw)
        all_routes.extend(routes)

    return all_routes


def nearest_route(routes: list, file_path: str, line_num: int) -> Optional[dict]:
    """Find the nearest route definition to a given file:line (for associating findings)."""
    file_routes = [r for r in routes if r["file_path"] == file_path]
    if not file_routes:
        return None

    # Find the route defined before (or closest to) the line
    before = [r for r in file_routes if r["line"] <= line_num]
    if before:
        return max(before, key=lambda r: r["line"])

    # If none before, take the first after
    after = sorted([r for r in file_routes if r["line"] > line_num], key=lambda r: r["line"])
    return after[0] if after else None


def format_routes_summary(routes: list) -> str:
    """Format routes as a Markdown table."""
    if not routes:
        return ""
    lines = ["## Discovered API Routes\n", "| Method | Path | File | Line |", "|--------|------|------|------|"]
    for r in sorted(routes, key=lambda x: (x["path"], x["method"])):
        lines.append(f"| {r['method']} | `{r['path']}` | `{Path(r['file_path']).name}` | {r['line']} |")
    return "\n".join(lines)


if __name__ == "__main__":
    import argparse
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from scripts.utils.files import enumerate_files

    parser = argparse.ArgumentParser()
    parser.add_argument("--path", required=True)
    parser.add_argument("--framework", default=None)
    args = parser.parse_args()

    base = Path(args.path)
    files = enumerate_files(base)
    routes = extract_routes_from_project(base, files)
    print(json.dumps(routes, indent=2))
    print(f"\n# Found {len(routes)} routes", file=sys.stderr)
