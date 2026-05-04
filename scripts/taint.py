#!/usr/bin/env python3
"""
Taint analysis helper — identifies sources, sinks, and potential taint paths.

Usage:
  python3 scripts/taint.py --file <path> [--lang <language>]

Outputs JSON with sources, sinks, and potential paths for agent verification.
"""

import argparse
import ast
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from scripts.utils.languages import detect_language
from scripts.utils.files import read_file, read_file_lines

# ── Python taint definitions ───────────────────────────────────────────────

PY_SOURCES = {
    "flask_request": [
        r"request\.args(?:\.get)?\s*\[",
        r"request\.args\.get\s*\(",
        r"request\.form(?:\.get)?\s*[\[(]",
        r"request\.json(?:\.get)?",
        r"request\.get_json\s*\(",
        r"request\.data\b",
        r"request\.files(?:\.get)?",
        r"request\.cookies(?:\.get)?",
        r"request\.headers(?:\.get)?",
        r"request\.values(?:\.get)?",
    ],
    "django_request": [
        r"request\.GET(?:\.get)?\s*[\[(]",
        r"request\.POST(?:\.get)?\s*[\[(]",
        r"request\.FILES(?:\.get)?\s*[\[(]",
        r"request\.COOKIES(?:\.get)?\s*[\[(]",
        r"request\.META(?:\.get)?\s*[\[(]",
        r"request\.body\b",
    ],
    "fastapi": [
        r"Query\(",
        r"Body\(",
        r"Form\(",
        r"File\(",
        r"Header\(",
        r"Cookie\(",
        r"Path\(",
    ],
    "generic": [
        r"\binput\s*\(",
        r"sys\.argv\b",
        r"sys\.stdin\.read\s*\(",
        r"os\.environ(?:\.get)?\s*[\[(]",
        r"os\.getenv\s*\(",
        r"open\s*\(.+['\"]r['\"]",
    ],
}

PY_SINKS = {
    "sqli": [
        (r"\.execute\s*\(\s*[f'\"]", "SQL execution with f-string/string"),
        (r"\.execute\s*\(\s*\w+\s*\+", "SQL execution with concatenation"),
        (r"\.execute\s*\(\s*\w+\s*%", "SQL execution with % formatting"),
        (r"\.raw\s*\(", "ORM raw SQL"),
        (r"\.extra\s*\(", "Django ORM extra()"),
        (r"RawSQL\s*\(", "Django RawSQL"),
        (r"text\s*\(\s*[f'\"]", "SQLAlchemy text() with f-string"),
    ],
    "cmdi": [
        (r"os\.system\s*\(", "os.system()"),
        (r"os\.popen\s*\(", "os.popen()"),
        (r"subprocess\.(run|call|Popen|check_output|check_call)\s*\(", "subprocess"),
        (r"eval\s*\(", "eval()"),
        (r"exec\s*\(", "exec()"),
        (r"__import__\s*\(", "__import__()"),
    ],
    "path_traversal": [
        (r"open\s*\(", "file open()"),
        (r"os\.path\.join\s*\(", "os.path.join()"),
        (r"send_file\s*\(", "Flask send_file()"),
        (r"send_from_directory\s*\(", "Flask send_from_directory()"),
        (r"pathlib\.Path\s*\(", "pathlib.Path()"),
    ],
    "ssti": [
        (r"render_template_string\s*\(", "Jinja2 render_template_string()"),
        (r"jinja2\.Template\s*\(", "Jinja2 Template()"),
        (r"jinja2\.Environment\s*\(\s*\)\.from_string\s*\(", "Jinja2 from_string()"),
        (r"Markup\s*\(", "Jinja2 Markup()"),
    ],
    "ssrf": [
        (r"requests\.(get|post|put|delete|patch|head|request)\s*\(", "requests HTTP call"),
        (r"urllib\.request\.urlopen\s*\(", "urllib.urlopen()"),
        (r"httpx\.(get|post|put|delete|patch)\s*\(", "httpx HTTP call"),
        (r"aiohttp\.ClientSession\s*\(", "aiohttp ClientSession"),
        (r"urllib\.urlopen\s*\(", "urllib2.urlopen()"),
    ],
    "deserialization": [
        (r"pickle\.loads?\s*\(", "pickle.load/loads()"),
        (r"yaml\.load\s*\(", "yaml.load() — unsafe"),
        (r"marshal\.loads?\s*\(", "marshal.load/loads()"),
        (r"shelve\.open\s*\(", "shelve.open()"),
    ],
    "xss": [
        (r"render_template_string\s*\(", "unsafe template rendering"),
        (r"Markup\s*\(", "Markup() — raw HTML"),
    ],
}

PY_SANITIZERS = {
    "sqli": [
        r"parameterize", r"%s\b", r"\?[,\)]", r":[\w]+\b",
        r"cursor\.execute\s*\([^,]+,\s*\(",  # execute with params tuple
    ],
    "cmdi": [r"shlex\.quote\s*\(", r"shell\s*=\s*False"],
    "path_traversal": [r"os\.path\.realpath\s*\(", r"os\.path\.abspath\s*\(", r"secure_filename\s*\("],
    "xss": [r"html\.escape\s*\(", r"markupsafe\.escape\s*\(", r"bleach\.clean\s*\(", r"escape\s*\("],
    "ssrf": [r"allowlist", r"whitelist", r"ALLOWED_HOSTS", r"internal_only"],
}

# ── JavaScript taint definitions ──────────────────────────────────────────

JS_SOURCES = [
    r"req\.(?:query|body|params|cookies|headers)",
    r"request\.(?:query|body|params|cookies|headers)",
    r"ctx\.(?:query|body|params|cookies|headers|request)",
    r"c\.(?:QueryParam|FormValue|PostForm|GetHeader|Cookie)\s*\(",  # Go Gin
    r"location\.(?:search|hash|href)",
    r"document\.(?:cookie|referrer|URL)",
    r"window\.name\b",
    r"localStorage\.getItem\s*\(",
    r"sessionStorage\.getItem\s*\(",
    r"event\.data\b",
]

JS_SINKS = {
    "xss": [
        r"\.innerHTML\s*=",
        r"\.outerHTML\s*=",
        r"document\.write\s*\(",
        r"insertAdjacentHTML\s*\(",
        r"dangerouslySetInnerHTML",
    ],
    "eval": [
        r"\beval\s*\(",
        r"new\s+Function\s*\(",
        r"setTimeout\s*\(\s*['\"`]",
        r"setInterval\s*\(\s*['\"`]",
    ],
    "sqli": [
        r"\.query\s*\(\s*[`'\"].*\$\{",
        r"\.query\s*\(\s*['\"].*\+",
        r"knex\.raw\s*\(",
        r"sequelize\.query\s*\(",
    ],
    "cmdi": [
        r"child_process\.exec\s*\(",
        r"\.execSync\s*\(",
        r"\.spawn\s*\(",
        r"\.spawnSync\s*\(",
    ],
    "path_traversal": [
        r"fs\.(?:readFile|createReadStream|writeFile|unlink)\s*\(",
        r"path\.join\s*\(",
        r"require\s*\(",
    ],
    "ssrf": [
        r"\bfetch\s*\(",
        r"axios\.(?:get|post|put|delete|request)\s*\(",
        r"http\.(?:get|request)\s*\(",
        r"https\.(?:get|request)\s*\(",
    ],
}

# ── PHP taint definitions ─────────────────────────────────────────────────

PHP_SOURCES = [
    r"\$_(?:GET|POST|REQUEST|FILES|COOKIE|SERVER)\s*\[",
    r"\$_SERVER\s*\[\s*['\"]HTTP_",
    r"file_get_contents\s*\(",
    r"fread\s*\(",
]

PHP_SINKS = {
    "sqli": [
        r"mysql(?:i)?_query\s*\(",
        r"\$(?:pdo|db|conn)\s*->\s*(?:query|exec|prepare)\s*\(",
        r"mysqli_(?:query|multi_query)\s*\(",
    ],
    "cmdi": [
        r"\bsystem\s*\(",
        r"\bexec\s*\(",
        r"\bshell_exec\s*\(",
        r"\bpassthru\s*\(",
        r"\bpopen\s*\(",
        r"preg_replace\s*\(.*['\"].*\/e['\"]",
    ],
    "xss": [
        r"\becho\s+",
        r"\bprint\s+",
        r"\bprintf\s*\(",
    ],
    "path_traversal": [
        r"\binclude\s*\(",
        r"\binclude_once\s*\(",
        r"\brequire\s*\(",
        r"\brequire_once\s*\(",
        r"\bfile_get_contents\s*\(",
        r"\bfopen\s*\(",
        r"\breadfile\s*\(",
    ],
}


def analyze_python_ast(content: str, file_path: str) -> dict:
    """Use Python AST to find source→sink chains within functions."""
    results = {"sources": [], "sinks": [], "potential_paths": []}

    try:
        tree = ast.parse(content)
    except SyntaxError:
        return results

    lines = content.splitlines()

    class TaintVisitor(ast.NodeVisitor):
        def __init__(self):
            self.tainted_vars = {}  # var_name -> (line, source_type)
            self.current_func = None

        def visit_FunctionDef(self, node):
            prev_func = self.current_func
            self.current_func = node.name
            saved_vars = dict(self.tainted_vars)
            self.generic_visit(node)
            self.tainted_vars = saved_vars
            self.current_func = prev_func

        visit_AsyncFunctionDef = visit_FunctionDef

        def _is_tainted_value(self, node) -> bool:
            if isinstance(node, ast.Name) and node.id in self.tainted_vars:
                return True
            if isinstance(node, (ast.BinOp, ast.JoinedStr)):
                return any(self._is_tainted_value(c) for c in ast.walk(node))
            if isinstance(node, ast.Call):
                return any(self._is_tainted_value(a) for a in node.args)
            return False

        def visit_Assign(self, node):
            value_src = ast.unparse(node.value) if hasattr(ast, "unparse") else ""

            # Check if right-hand side is a source
            for src_type, patterns in PY_SOURCES.items():
                for pattern in patterns:
                    if re.search(pattern, value_src):
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                self.tainted_vars[target.id] = (node.lineno, src_type)
                                results["sources"].append({
                                    "line": node.lineno,
                                    "variable": target.id,
                                    "source_type": src_type,
                                    "code": lines[node.lineno - 1].strip() if node.lineno <= len(lines) else "",
                                })
            # Propagate taint through assignments
            if self._is_tainted_value(node.value):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        # Propagate from the tainted variable
                        for v in ast.walk(node.value):
                            if isinstance(v, ast.Name) and v.id in self.tainted_vars:
                                self.tainted_vars[target.id] = self.tainted_vars[v.id]
                                break

            self.generic_visit(node)

        def visit_Call(self, node):
            call_str = ast.unparse(node) if hasattr(ast, "unparse") else ""

            # Check if call is a sink
            for sink_type, sink_list in PY_SINKS.items():
                for pattern, sink_name in sink_list:
                    if re.search(pattern, call_str):
                        # Check if any argument is tainted
                        tainted_args = []
                        for arg in list(node.args) + [kw.value for kw in node.keywords]:
                            for v in ast.walk(arg):
                                if isinstance(v, ast.Name) and v.id in self.tainted_vars:
                                    src_line, src_type = self.tainted_vars[v.id]
                                    tainted_args.append((v.id, src_line, src_type))

                        if tainted_args:
                            line_code = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""
                            results["sinks"].append({
                                "line": node.lineno,
                                "sink_type": sink_type,
                                "sink_name": sink_name,
                                "code": line_code,
                            })
                            for var, src_line, src_type in tainted_args:
                                results["potential_paths"].append({
                                    "source_line": src_line,
                                    "source_type": src_type,
                                    "tainted_var": var,
                                    "sink_line": node.lineno,
                                    "sink_type": sink_type,
                                    "sink_name": sink_name,
                                    "confidence": "possible",
                                    "source_code": lines[src_line - 1].strip() if src_line <= len(lines) else "",
                                    "sink_code": line_code,
                                    "function": self.current_func,
                                })
            self.generic_visit(node)

    visitor = TaintVisitor()
    visitor.visit(tree)
    return results


def analyze_with_patterns(content: str, file_path: str, language: str) -> dict:
    """Pattern-based taint analysis for non-Python languages."""
    results = {"sources": [], "sinks": [], "potential_paths": []}
    lines = content.splitlines()

    if language in ("javascript", "typescript"):
        sources = JS_SOURCES
        sinks = JS_SINKS
    elif language == "php":
        sources = PHP_SOURCES
        sinks = PHP_SINKS
    else:
        return results

    source_lines = set()
    for i, line in enumerate(lines, start=1):
        for pattern in (sources if isinstance(sources, list) else []):
            if re.search(pattern, line):
                results["sources"].append({"line": i, "code": line.strip(), "pattern": pattern})
                source_lines.add(i)

    for i, line in enumerate(lines, start=1):
        for sink_type, sink_patterns in sinks.items():
            for pattern in sink_patterns:
                if re.search(pattern, line):
                    results["sinks"].append({
                        "line": i, "sink_type": sink_type,
                        "code": line.strip(), "pattern": pattern,
                    })
                    # Flag as potential path if source appeared in nearby lines
                    nearby_sources = [s for s in results["sources"] if abs(s["line"] - i) <= 20]
                    if nearby_sources:
                        for src in nearby_sources:
                            results["potential_paths"].append({
                                "source_line": src["line"],
                                "sink_line": i,
                                "sink_type": sink_type,
                                "confidence": "possible",
                                "source_code": src["code"],
                                "sink_code": line.strip(),
                                "note": "Pattern proximity — requires manual verification",
                            })
    return results


def analyze_file(file_path: str, language: str = None) -> dict:
    p = Path(file_path)
    if not language:
        language = detect_language(p)

    content = read_file(p)
    if not content:
        return {"error": "could not read file", "file": file_path}

    if language == "python":
        results = analyze_python_ast(content, file_path)
    else:
        results = analyze_with_patterns(content, file_path, language)

    results["file"] = file_path
    results["language"] = language
    results["total_sources"] = len(results["sources"])
    results["total_sinks"] = len(results["sinks"])
    results["total_potential_paths"] = len(results["potential_paths"])

    return results


def main():
    parser = argparse.ArgumentParser(description="Code-VulnScan taint analyzer")
    parser.add_argument("--file", required=True, help="File to analyze")
    parser.add_argument("--lang", help="Language override")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    args = parser.parse_args()

    results = analyze_file(args.file, args.lang)

    indent = 2 if args.pretty else None
    print(json.dumps(results, indent=indent))

    if results.get("potential_paths"):
        print(f"\n[!] Found {len(results['potential_paths'])} potential taint paths — manual verification required",
              file=sys.stderr)
        print("    Each path must be verified by reading the actual code in the agent sub-skill.", file=sys.stderr)


if __name__ == "__main__":
    main()
