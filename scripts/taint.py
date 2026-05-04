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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

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
    "starlette": [
        r"request\.query_params(?:\.get)?\s*[\[(]",
        r"request\.path_params(?:\.get)?\s*[\[(]",
        r"await\s+request\.body\s*\(",
        r"await\s+request\.json\s*\(",
        r"await\s+request\.form\s*\(",
    ],
    "quart": [
        r"await\s+request\.get_data\s*\(",
        r"await\s+request\.get_json\s*\(",
        r"request\.args(?:\.get)?\s*[\[(]",
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
        (r"text\s*\(\s*f['\"]", "SQLAlchemy text() with f-string"),
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
        # NEW:
        r"psycopg2\.sql\.(?:Identifier|Literal|SQL)\s*\(",
        r"sqlalchemy\.text\s*\([^)]+\)\s*,",  # text() with bound params
        r"\.bindparams\s*\(",
    ],
    "cmdi": [
        r"shlex\.quote\s*\(", r"shell\s*=\s*False",
        # NEW:
        r"pipes\.quote\s*\(",
        r"subprocess\.run\s*\(\s*\[",   # list form = safe
        r"subprocess\.Popen\s*\(\s*\[",  # list form = safe
    ],
    "path_traversal": [
        r"os\.path\.realpath\s*\(", r"os\.path\.abspath\s*\(", r"secure_filename\s*\(",
        # NEW:
        r"werkzeug\.utils\.secure_filename\s*\(",
        r"os\.path\.normpath\s*\(",
        r"\.startswith\s*\(\s*safe",  # safe_dir check pattern
        r"\.startswith\s*\(\s*BASE",
        r"\.startswith\s*\(\s*ALLOWED",
    ],
    "xss": [
        r"html\.escape\s*\(", r"markupsafe\.escape\s*\(", r"bleach\.clean\s*\(", r"escape\s*\(",
        # NEW:
        r"flask\.Markup\.escape\s*\(",
        r"django\.utils\.html\.escape\s*\(",
        r"markupsafe\.Markup\.escape\s*\(",
        r"cgi\.escape\s*\(",
    ],
    "ssrf": [
        r"allowlist", r"whitelist", r"ALLOWED_HOSTS", r"internal_only",
        # NEW:
        r"ipaddress\.ip_address\s*\(",
        r"furl\s*\(",
        r"urllib\.parse\.urlparse\s*\(",
    ],
    "deserialization": [
        # NEW:
        r"yaml\.safe_load\s*\(",  # safe alternative to yaml.load
        r"json\.loads\s*\(",      # always safe (no code execution)
        r"json\.load\s*\(",
    ],
}

# Sanitizer calls that break taint chains (used in _is_tainted_value)
_PY_SANITIZER_CALLS = [
    r"shlex\.quote\s*\(",
    r"pipes\.quote\s*\(",
    r"html\.escape\s*\(",
    r"markupsafe\.escape\s*\(",
    r"bleach\.clean\s*\(",
    r"flask\.Markup\.escape\s*\(",
    r"django\.utils\.html\.escape\s*\(",
    r"markupsafe\.Markup\.escape\s*\(",
    r"cgi\.escape\s*\(",
    r"os\.path\.realpath\s*\(",
    r"os\.path\.abspath\s*\(",
    r"werkzeug\.utils\.secure_filename\s*\(",
    r"secure_filename\s*\(",
    r"yaml\.safe_load\s*\(",
    r"json\.loads\s*\(",
    r"json\.load\s*\(",
    r"psycopg2\.sql\.(?:Identifier|Literal|SQL)\s*\(",
    r"ipaddress\.ip_address\s*\(",
]

# ── ORM safe-call patterns (Task 1.3) ─────────────────────────────────────

PY_ORM_SAFE_PATTERNS = {
    "django": [
        r"\.objects\.filter\s*\(",
        r"\.objects\.get\s*\(",
        r"\.objects\.create\s*\(",
        r"\.objects\.update\s*\(",
        r"\.objects\.exclude\s*\(",
        r"\.objects\.annotate\s*\(",
        r"QuerySet\.filter\s*\(",
    ],
    "sqlalchemy": [
        r"session\.query\s*\(",
        r"\.filter\s*\(",
        r"select\s*\(",
        r"insert\s*\(",
        r"update\s*\(",
        r"db\.session\.",
    ],
    "peewee": [
        r"\.select\s*\(",
        r"\.where\s*\(",
        r"\.get\s*\(",
    ],
    "tortoise": [
        r"\.filter\s*\(",
        r"\.get_or_none\s*\(",
        r"\.create\s*\(",
    ],
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
    # NEW (Task 1.4):
    r"process\.argv\b",
    r"req\.files\b",
    r"event\.(?:target|currentTarget)\.value\b",
    r"URLSearchParams\s*\(",
    r"new\s+URL\s*\(",
]

JS_SINKS = {
    "xss": [
        r"\.innerHTML\s*=",
        r"\.outerHTML\s*=",
        r"document\.write\s*\(",
        r"insertAdjacentHTML\s*\(",
        r"dangerouslySetInnerHTML",
        # NEW (Task 1.4):
        r"\.setAttribute\s*\(\s*['\"]on",
        r"location\.href\s*=",
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
        # NEW (Task 1.4):
        r"mongoose\.connection\.db\.command\s*\(",
        r"collection\.find\s*\(\s*\{[^}]*\$where",
    ],
    "cmdi": [
        r"child_process\.exec\s*\(",
        r"\.execSync\s*\(",
        r"\.spawn\s*\(",
        r"\.spawnSync\s*\(",
        # NEW (Task 1.4):
        r"require\s*\(\s*(?:req|user)",
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
    "proto_pollution": [
        # NEW (Task 1.4):
        r"Object\.assign\s*\(\s*\{\s*\}\s*,\s*req\.",
        r"Object\.assign\s*\(\s*\w+\s*,\s*req\.",
        r"\[.*\]\s*=\s*req\.",
    ],
    "open_redirect": [
        r"res\.redirect\s*\(",
        r"response\.redirect\s*\(",
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

# ── Ruby taint definitions ────────────────────────────────────────────────

RUBY_SOURCES = [
    r"params\[",
    r"params\.\w+",
    r"request\.(?:params|query_string|body|headers|env)",
    r"ENV\[",
    r"\$stdin\b",
    r"ARGV\b",
    r"cookies\[",
    r"session\[",
    r"gets\s*\(",
]

RUBY_SINKS = {
    "sqli": [
        r"\.where\s*\(\s*['\"].*#\{",           # ActiveRecord where with interpolation
        r"\.find_by_sql\s*\(",
        r"ActiveRecord::Base\.connection\.execute\s*\(",
        r"\.execute\s*\(\s*['\"].*#\{",
    ],
    "cmdi": [
        r"\bsystem\s*\(",
        r"\bexec\s*\(",
        r"`[^`]*#\{",                             # backtick interpolation
        r"\bspawn\s*\(",
        r"IO\.popen\s*\(",
        r"Open3\.",
        r"Kernel\.system\s*\(",
    ],
    "xss": [
        r"render\s+text:",
        r"render\s+html:",
        r"\.html_safe\b",
        r"raw\s*\(",
        r"<%= .* %>",
    ],
    "path_traversal": [
        r"File\.read\s*\(",
        r"File\.open\s*\(",
        r"File\.join\s*\(",
        r"IO\.read\s*\(",
        r"send_file\s*\(",
        r"render\s+file:",
    ],
    "ssrf": [
        r"Net::HTTP\.get\s*\(",
        r"Net::HTTP\.post\s*\(",
        r"open\s*\(\s*['\"]?http",
        r"RestClient\.\w+\s*\(",
        r"HTTParty\.\w+\s*\(",
        r"Faraday\.new\s*\(",
    ],
    "deserialization": [
        r"Marshal\.load\s*\(",
        r"YAML\.load\s*\(",
        r"JSON\.parse\s*\(",  # low risk but track
    ],
}

# ── C# taint definitions ──────────────────────────────────────────────────

CS_SOURCES = [
    r"Request\.(?:QueryString|Form|Params|Headers|Cookies)\[",
    r"Request\.Query\[",
    r"Request\.Form\[",
    r"HttpContext\.Request\.",
    r"\[FromQuery\]",
    r"\[FromBody\]",
    r"\[FromRoute\]",
    r"\[FromForm\]",
    r"Environment\.GetEnvironmentVariable\s*\(",
    r"Console\.ReadLine\s*\(",
    r"args\[",                  # command-line args
]

CS_SINKS = {
    "sqli": [
        r"SqlCommand\s*\(\s*.*\+",               # SqlCommand with concatenation
        r"new\s+SqlCommand\s*\(\s*\$\"",         # SqlCommand with interpolation
        r"ExecuteQuery\s*\(\s*.*\+",
        r"\.ExecuteNonQuery\s*\(",
        r"SqlDataAdapter\s*\(\s*.*\+",
        r"NpgsqlCommand\s*\(\s*.*\+",
    ],
    "cmdi": [
        r"Process\.Start\s*\(",
        r"ProcessStartInfo\s*\(",
        r"cmd\.ExecuteReader\s*\(",
    ],
    "xss": [
        r"Response\.Write\s*\(",
        r"HtmlHelper\.Raw\s*\(",
        r"@Html\.Raw\s*\(",
        r"MvcHtmlString\.Create\s*\(",
    ],
    "path_traversal": [
        r"File\.ReadAllText\s*\(",
        r"File\.Open\s*\(",
        r"File\.ReadAllBytes\s*\(",
        r"new\s+FileStream\s*\(",
        r"Path\.Combine\s*\(",
        r"Directory\.GetFiles\s*\(",
    ],
    "ssrf": [
        r"new\s+HttpClient\s*\(",
        r"WebClient\.DownloadString\s*\(",
        r"HttpWebRequest\.Create\s*\(",
    ],
    "deserialization": [
        r"BinaryFormatter\.Deserialize\s*\(",
        r"JavaScriptSerializer\.Deserialize\s*\(",
        r"JsonConvert\.DeserializeObject<",
        r"XmlSerializer\.Deserialize\s*\(",
        r"DataContractSerializer\.ReadObject\s*\(",
    ],
    "xxe": [
        r"XmlDocument\.Load\s*\(",
        r"XmlReader\.Create\s*\(",                # without XmlReaderSettings
        r"XDocument\.Load\s*\(",
    ],
}

# ── Go taint definitions ──────────────────────────────────────────────────

GO_SOURCES = [
    r'c\.Query\s*\(',          # Gin
    r'c\.Param\s*\(',          # Gin
    r'c\.PostForm\s*\(',       # Gin
    r'r\.FormValue\s*\(',      # stdlib net/http
    r'r\.URL\.Query\(\)',      # stdlib net/http
    r'c\.Request\.FormValue\s*\(',  # Chi/Fiber
    r'ctx\.Query\s*\(',        # Echo
    r'ctx\.Param\s*\(',        # Echo
]

GO_SINKS = {
    "sqli": [
        r'\.Query\s*\(\s*(?:fmt\.Sprintf|fmt\.Printf)',
        r'db\.Exec\s*\(\s*fmt\.Sprintf',
    ],
    "cmdi": [
        r'exec\.Command\s*\(',
        r'exec\.CommandContext\s*\(',
    ],
    "ssrf": [
        r'http\.Get\s*\(',
        r'http\.Post\s*\(',
        r'client\.Do\s*\(',
    ],
    "path_traversal": [
        r'os\.Open\s*\(',
        r'ioutil\.ReadFile\s*\(',
        r'os\.ReadFile\s*\(',
    ],
}


# ── Interprocedural analysis helpers (Task 1.1) ────────────────────────────

@dataclass
class FunctionSummary:
    name: str
    params_tainted: Set[int] = field(default_factory=set)  # param indices that carry taint in
    returns_tainted: bool = False


def _build_function_summaries(tree: ast.AST, sources: dict) -> Dict[str, FunctionSummary]:
    """Build interprocedural function summaries via fixpoint iteration (up to 3 passes)."""
    summaries: Dict[str, FunctionSummary] = {}

    # Collect all top-level and nested function defs
    func_nodes: List[ast.FunctionDef] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_nodes.append(node)
            summaries[node.name] = FunctionSummary(name=node.name)

    def _unparse(node) -> str:
        if hasattr(ast, "unparse"):
            try:
                return ast.unparse(node)
            except Exception:
                return ""
        return ""

    def _is_source_expr(expr_str: str) -> bool:
        for src_type, patterns in sources.items():
            for pattern in patterns:
                if re.search(pattern, expr_str):
                    return True
        return False

    # Up to 3 fixpoint iterations
    for _iteration in range(3):
        changed = False
        for func_node in func_nodes:
            summary = summaries[func_node.name]
            param_names = [arg.arg for arg in func_node.args.args]

            # Simulate taint within the function
            local_tainted: Set[str] = set()

            # Collect assignments and calls inside this function (shallow walk)
            for child in ast.walk(func_node):
                if isinstance(child, ast.Assign):
                    rhs_str = _unparse(child.value)
                    if _is_source_expr(rhs_str):
                        for target in child.targets:
                            if isinstance(target, ast.Name):
                                local_tainted.add(target.id)
                    # Propagate from tainted vars
                    for v in ast.walk(child.value):
                        if isinstance(v, ast.Name) and v.id in local_tainted:
                            for target in child.targets:
                                if isinstance(target, ast.Name):
                                    local_tainted.add(target.id)
                            break
                    # Propagate taint via subscript/attribute on tainted var
                    if isinstance(child.value, (ast.Subscript, ast.Attribute)):
                        root = child.value.value if isinstance(child.value, ast.Attribute) else child.value.value
                        if isinstance(root, ast.Name) and root.id in local_tainted:
                            for target in child.targets:
                                if isinstance(target, ast.Name):
                                    local_tainted.add(target.id)

                elif isinstance(child, ast.Return):
                    if child.value is not None:
                        for v in ast.walk(child.value):
                            if isinstance(v, ast.Name) and v.id in local_tainted:
                                if not summary.returns_tainted:
                                    summary.returns_tainted = True
                                    changed = True
                                break
                        # Also check if any param is returned directly
                        for idx, pname in enumerate(param_names):
                            if idx in summary.params_tainted:
                                for v in ast.walk(child.value):
                                    if isinstance(v, ast.Name) and v.id == pname:
                                        if not summary.returns_tainted:
                                        	summary.returns_tainted = True
                                        	changed = True
                                        break

            # Check if params flow to sinks (mark which params carry taint)
            for child in ast.walk(func_node):
                if isinstance(child, ast.Call):
                    call_str = _unparse(child)
                    # Check if any param is passed to a sink — if so, mark it
                    for sink_type, sink_list in PY_SINKS.items():
                        for pattern, _ in sink_list:
                            if re.search(pattern, call_str):
                                for arg in child.args:
                                    for v in ast.walk(arg):
                                        if isinstance(v, ast.Name) and v.id in param_names:
                                            idx = param_names.index(v.id)
                                            if idx not in summary.params_tainted:
                                                summary.params_tainted.add(idx)
                                                changed = True

                    # If calling another known function whose result is returned
                    if isinstance(child.func, ast.Name) and child.func.id in summaries:
                        callee_summary = summaries[child.func.id]
                        if callee_summary.returns_tainted:
                            local_tainted.add("__call_result__")

        if not changed:
            break

    return summaries


def analyze_python_ast(content: str, file_path: str) -> dict:
    """Use Python AST to find source→sink chains within functions."""
    results = {"sources": [], "sinks": [], "potential_paths": []}

    try:
        tree = ast.parse(content)
    except SyntaxError:
        return results

    lines = content.splitlines()

    # ── Task 1.1: Build interprocedural function summaries ─────────────────
    function_summaries = _build_function_summaries(tree, PY_SOURCES)

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
            if isinstance(node, (ast.BinOp, ast.JoinedStr, ast.FormattedValue)):
                # Use iter_child_nodes (not walk) to avoid yielding the node itself → no infinite recursion
                return any(self._is_tainted_value(c) for c in ast.iter_child_nodes(node))
            if isinstance(node, ast.Call):
                # If the call itself is a sanitizer, it neutralizes taint
                _call_str = ast.unparse(node) if hasattr(ast, "unparse") else ""
                if _call_str and any(re.search(p, _call_str) for p in _PY_SANITIZER_CALLS):
                    return False
                # Task 1.1: check interprocedural — if calling a known function
                # with tainted args and it returns tainted, this call is tainted
                func_name = None
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                if func_name and func_name in function_summaries:
                    summary = function_summaries[func_name]
                    for idx, arg in enumerate(node.args):
                        if idx in summary.params_tainted or self._is_tainted_value(arg):
                            if summary.returns_tainted:
                                return True
                return any(self._is_tainted_value(a) for a in node.args)
            # Task 1.2: Subscript taint (e.g. data["q"] where data is tainted)
            if isinstance(node, ast.Subscript):
                return self._is_tainted_value(node.value)
            # Task 1.2: Attribute taint (e.g. obj.name where obj is tainted)
            if isinstance(node, ast.Attribute):
                return self._is_tainted_value(node.value)
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
            # Propagate taint through assignments (including subscript/attribute — Task 1.2)
            if self._is_tainted_value(node.value):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        # Find the originating tainted variable
                        origin = None
                        for v in ast.walk(node.value):
                            if isinstance(v, ast.Name) and v.id in self.tainted_vars:
                                origin = self.tainted_vars[v.id]
                                break
                        if origin:
                            self.tainted_vars[target.id] = origin

            # Task 1.2: Handle container assignment — when whole container is tainted
            # (e.g. data = request.args — mark attribute accesses later as tainted)
            # This is handled by _is_tainted_value checking ast.Attribute/ast.Subscript.

            self.generic_visit(node)

        def visit_Call(self, node):
            call_str = ast.unparse(node) if hasattr(ast, "unparse") else ""

            # Task 1.2: check if method is called on a tainted object
            # e.g. tainted_obj.execute(...)  or tainted_obj.format(...)
            caller_is_tainted = False
            if isinstance(node.func, ast.Attribute):
                caller_is_tainted = self._is_tainted_value(node.func.value)

            # Check if call is a sink
            for sink_type, sink_list in PY_SINKS.items():
                for pattern, sink_name in sink_list:
                    if re.search(pattern, call_str):
                        # Task 1.3: ORM safe-call recognition — skip if safe ORM pattern
                        # with only keyword args (no tainted positional string concat)
                        if sink_type == "sqli":
                            is_orm_safe = False
                            for orm_name, orm_patterns in PY_ORM_SAFE_PATTERNS.items():
                                for orm_pattern in orm_patterns:
                                    if re.search(orm_pattern, call_str):
                                        # Check that there's no raw string concatenation with tainted var
                                        has_tainted_positional_str = False
                                        for arg in node.args:
                                            arg_str = ast.unparse(arg) if hasattr(ast, "unparse") else ""
                                            if self._is_tainted_value(arg) and isinstance(arg, (ast.JoinedStr, ast.BinOp)):
                                                has_tainted_positional_str = True
                                                break
                                        if not has_tainted_positional_str:
                                            is_orm_safe = True
                                            break
                                if is_orm_safe:
                                    break
                            if is_orm_safe:
                                continue

                        # Check if any argument is tainted
                        tainted_args = []
                        all_args = list(node.args) + [kw.value for kw in node.keywords]

                        # Also treat the call as tainted if the caller object is tainted
                        if caller_is_tainted:
                            # Synthesize a taint entry for the receiver object
                            for v in ast.walk(node.func.value):
                                if isinstance(v, ast.Name) and v.id in self.tainted_vars:
                                    src_line, src_type = self.tainted_vars[v.id]
                                    tainted_args.append((v.id, src_line, src_type))
                                    break

                        for arg in all_args:
                            for v in ast.walk(arg):
                                if isinstance(v, ast.Name) and v.id in self.tainted_vars:
                                    src_line, src_type = self.tainted_vars[v.id]
                                    tainted_args.append((v.id, src_line, src_type))
                            # Task 1.2: also check if arg itself is a tainted subscript/attribute
                            if isinstance(arg, (ast.Subscript, ast.Attribute)) and self._is_tainted_value(arg):
                                arg_str = ast.unparse(arg) if hasattr(ast, "unparse") else "?"
                                # Find origin
                                root = arg
                                while isinstance(root, (ast.Subscript, ast.Attribute)):
                                    root = root.value
                                if isinstance(root, ast.Name) and root.id in self.tainted_vars:
                                    src_line, src_type = self.tainted_vars[root.id]
                                    tainted_args.append((root.id, src_line, src_type))

                        if tainted_args:
                            line_code = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""
                            results["sinks"].append({
                                "line": node.lineno,
                                "sink_type": sink_type,
                                "sink_name": sink_name,
                                "code": line_code,
                            })
                            for var, src_line, src_type in tainted_args:
                                # Task 1.1: detect if this is a cross-function path
                                is_interprocedural = (
                                    src_type in function_summaries or
                                    (self.current_func is not None and var not in
                                     _get_func_local_vars(tree, self.current_func))
                                )
                                path_entry = {
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
                                }
                                results["potential_paths"].append(path_entry)

                        # Task 1.1: cross-function call — if calling a known function
                        # with tainted args and it returns tainted, taint the result variable
                        func_name = None
                        if isinstance(node.func, ast.Name):
                            func_name = node.func.id
                        if func_name and func_name in function_summaries:
                            summary = function_summaries[func_name]
                            has_tainted_param = any(
                                self._is_tainted_value(a) for a in node.args
                            )
                            if has_tainted_param and summary.returns_tainted:
                                # The result of this call is tainted — handled in visit_Assign
                                pass

            self.generic_visit(node)

    visitor = TaintVisitor()
    visitor.visit(tree)
    return results


def _get_func_local_vars(tree: ast.AST, func_name: str) -> Set[str]:
    """Get all variable names assigned within a specific function."""
    local_vars: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func_name:
            for child in ast.walk(node):
                if isinstance(child, ast.Assign):
                    for target in child.targets:
                        if isinstance(target, ast.Name):
                            local_vars.add(target.id)
            break
    return local_vars


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
    elif language == "go":
        sources = GO_SOURCES
        sinks = GO_SINKS
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


# ── Task 1.4: JS/TS destructuring pattern for variable tracking ────────────

# Matches:  const { name, other } = req.body
_JS_DESTRUCTURE_OBJ_RE = re.compile(
    r"(?:const|let|var)\s*\{([^}]+)\}\s*=\s*(.+)"
)
# Matches:  const [first, second] = req.body.items
_JS_DESTRUCTURE_ARR_RE = re.compile(
    r"(?:const|let|var)\s*\[([^\]]+)\]\s*=\s*(.+)"
)


# Inline sanitizers: if a sink line contains one of these patterns for the given
# language+sink_type, the finding is considered sanitized and skipped.
_LANG_INLINE_SANITIZERS = {
    "php": {
        "xss": [r"\bhtmlspecialchars\s*\(", r"\bhtmlentities\s*\(", r"\bstrip_tags\s*\(", r"\besc_html\s*\("],
        "sqli": [r"->prepare\s*\(", r"\bpg_escape_string\s*\(", r"\bmysqli_real_escape_string\s*\("],
        "path_traversal": [r"\bbasename\s*\(", r"\brealpath\s*\("],
    },
    "javascript": {
        "xss": [r"\bDOMPurify\.sanitize\s*\(", r"\bescapeHtml\s*\(", r"\bsanitizeHtml\s*\("],
    },
}

# Sanitizer calls in RHS of assignment: don't propagate taint through these
_LANG_RHS_SANITIZERS = {
    "php": [
        r"\bhtmlspecialchars\s*\(", r"\bhtmlentities\s*\(", r"\bstrip_tags\s*\(",
        r"\bbasename\s*\(", r"\brealpath\s*\(",
        r"->prepare\s*\(", r"\bpg_escape_string\s*\(", r"\bmysqli_real_escape_string\s*\(",
        r"\bintval\s*\(", r"\bfloatval\s*\(", r"\babs\s*\(",
    ],
    "javascript": [
        r"\bDOMPurify\.sanitize\s*\(", r"\bescapeHtml\s*\(", r"\bencodeURIComponent\s*\(",
        r"\bparseInt\s*\(", r"\bparseFloat\s*\(", r"\bNumber\s*\(",
    ],
}


def analyze_with_variable_tracking(content: str, file_path: str, language: str) -> dict:
    """Variable-aware taint analysis for JavaScript/TypeScript, PHP, Ruby, C#.

    Tracks assignments so that taint flows through variable names instead of
    relying purely on source/sink proximity.  Falls back to
    `analyze_with_patterns` when the language is not supported here.
    """
    if language not in ("javascript", "typescript", "php", "ruby", "csharp"):
        return analyze_with_patterns(content, file_path, language)

    results = {"sources": [], "sinks": [], "potential_paths": []}
    lines = content.splitlines()

    if language in ("javascript", "typescript"):
        sources = JS_SOURCES
        sinks = JS_SINKS
        # JS/TS assignment: const/let/var name = <rhs>   or   name = <rhs>
        assign_re = re.compile(
            r"(?:const|let|var)\s+(\w+)\s*=\s*(.+)"
            r"|"
            r"(\w+)\s*=\s*(.+)"
        )
        # PHP-style variable prefix not applicable
        php_mode = False
    elif language == "php":
        sources = PHP_SOURCES
        sinks = PHP_SINKS
        # PHP: $var = <rhs>
        assign_re = re.compile(r"\$(\w+)\s*=\s*(.+)")
        php_mode = True
    elif language == "ruby":
        sources = RUBY_SOURCES
        sinks = RUBY_SINKS
        # Ruby assignment: var = <rhs>, @var = <rhs>, @@var = <rhs>
        assign_re = re.compile(
            r"@@?(\w+)\s*=\s*(.+)"
            r"|"
            r"(\w+)\s*=\s*(.+)"
        )
        php_mode = False
    else:  # csharp
        sources = CS_SOURCES
        sinks = CS_SINKS
        # C# assignment: var/string/int/object/dynamic name = <rhs>  or  name = <rhs>
        assign_re = re.compile(
            r"(?:var|string|int|object|dynamic)\s+(\w+)\s*=\s*(.+)"
            r"|"
            r"(\w+)\s*=\s*(.+)"
        )
        php_mode = False

    # tainted_vars maps var_name -> {"source_line": int, "source_code": str, "pattern": str}
    tainted_vars: dict = {}

    def _var_in_line(var_name: str, line: str) -> bool:
        """Check whether a (possibly tainted) variable appears in a line."""
        if php_mode:
            return bool(re.search(r'\$' + re.escape(var_name) + r'\b', line))
        return bool(re.search(r'\b' + re.escape(var_name) + r'\b', line))

    for i, line in enumerate(lines, start=1):
        # ── Step 1: detect assignments that capture a source ───────────────
        m = assign_re.search(line)
        if m:
            if php_mode:
                var_name = m.group(1)
                rhs = m.group(2) or ""
            else:
                # Two alternatives: (const/let/var form) or (bare assignment)
                var_name = m.group(1) or m.group(3)
                rhs = m.group(2) or m.group(4) or ""

            if var_name and rhs:
                for src_pattern in (sources if isinstance(sources, list) else []):
                    if re.search(src_pattern, rhs):
                        tainted_vars[var_name] = {
                            "source_line": i,
                            "source_code": line.strip(),
                            "pattern": src_pattern,
                        }
                        results["sources"].append({
                            "line": i,
                            "variable": var_name,
                            "code": line.strip(),
                            "pattern": src_pattern,
                        })
                        break

                # Propagate: if RHS contains a tainted var, new var is also tainted
                # BUT skip propagation if the RHS applies a known sanitizer
                _rhs_sanitizers = _LANG_RHS_SANITIZERS.get(language, [])
                _rhs_sanitized = any(re.search(sp, rhs) for sp in _rhs_sanitizers)
                if not _rhs_sanitized:
                    for existing_var, info in list(tainted_vars.items()):
                        if _var_in_line(existing_var, rhs):
                            if var_name not in tainted_vars:
                                tainted_vars[var_name] = {
                                    "source_line": info["source_line"],
                                    "source_code": info["source_code"],
                                    "pattern": info["pattern"],
                                }
                            break

        # ── Task 1.4: Destructuring assignment propagation ─────────────────
        if not php_mode:
            # Object destructuring: const { name, age } = req.body
            dm = _JS_DESTRUCTURE_OBJ_RE.search(line)
            if dm:
                destructured_names_raw = dm.group(1)
                dest_rhs = dm.group(2).strip()
                is_tainted_rhs = any(
                    re.search(src_pattern, dest_rhs)
                    for src_pattern in (sources if isinstance(sources, list) else [])
                ) or any(
                    _var_in_line(tv, dest_rhs) for tv in tainted_vars
                )
                if is_tainted_rhs:
                    # Parse destructured names (handle aliases: { foo: bar })
                    for raw_name in destructured_names_raw.split(","):
                        raw_name = raw_name.strip()
                        if not raw_name:
                            continue
                        # alias form "key: localVar" — take the local var name
                        if ":" in raw_name:
                            local_var = raw_name.split(":", 1)[1].strip().split()[0]
                        else:
                            local_var = raw_name.split()[0].lstrip(".")
                        # Strip any default value (= expr)
                        local_var = local_var.split("=")[0].strip()
                        if local_var and re.match(r"^\w+$", local_var):
                            origin_info = None
                            for tv, info in tainted_vars.items():
                                if _var_in_line(tv, dest_rhs):
                                    origin_info = info
                                    break
                            if origin_info is None:
                                # RHS is a direct source
                                origin_info = {
                                    "source_line": i,
                                    "source_code": line.strip(),
                                    "pattern": dest_rhs,
                                }
                            tainted_vars[local_var] = origin_info
                            if not any(s["line"] == i and s.get("variable") == local_var for s in results["sources"]):
                                results["sources"].append({
                                    "line": i,
                                    "variable": local_var,
                                    "code": line.strip(),
                                    "pattern": dest_rhs,
                                })

            # Array destructuring: const [first] = req.body.items
            am = _JS_DESTRUCTURE_ARR_RE.search(line)
            if am:
                arr_names_raw = am.group(1)
                arr_rhs = am.group(2).strip()
                is_tainted_rhs = any(
                    re.search(src_pattern, arr_rhs)
                    for src_pattern in (sources if isinstance(sources, list) else [])
                ) or any(
                    _var_in_line(tv, arr_rhs) for tv in tainted_vars
                )
                if is_tainted_rhs:
                    for raw_name in arr_names_raw.split(","):
                        raw_name = raw_name.strip().split("=")[0].strip()
                        if raw_name and re.match(r"^\w+$", raw_name):
                            origin_info = None
                            for tv, info in tainted_vars.items():
                                if _var_in_line(tv, arr_rhs):
                                    origin_info = info
                                    break
                            if origin_info is None:
                                origin_info = {
                                    "source_line": i,
                                    "source_code": line.strip(),
                                    "pattern": arr_rhs,
                                }
                            tainted_vars[raw_name] = origin_info
                            if not any(s["line"] == i and s.get("variable") == raw_name for s in results["sources"]):
                                results["sources"].append({
                                    "line": i,
                                    "variable": raw_name,
                                    "code": line.strip(),
                                    "pattern": arr_rhs,
                                })

        # ── Step 2: also record bare source appearances (no assignment) ────
        for src_pattern in (sources if isinstance(sources, list) else []):
            if re.search(src_pattern, line):
                # Only add if we didn't already catch it as an assignment rhs
                if not any(s["line"] == i for s in results["sources"]):
                    results["sources"].append({
                        "line": i,
                        "variable": None,
                        "code": line.strip(),
                        "pattern": src_pattern,
                    })

        # ── Step 3: check sinks, variable-tracking only (no proximity fallback) ───
        for sink_type, sink_patterns in sinks.items():
            for sink_pattern in sink_patterns:
                if not re.search(sink_pattern, line):
                    continue

                # Check inline sanitizer: if the sink line itself applies a sanitizer, skip
                _inline_sanz = _LANG_INLINE_SANITIZERS.get(language, {}).get(sink_type, [])
                if _inline_sanz and any(re.search(sp, line) for sp in _inline_sanz):
                    continue

                # Record the sink regardless
                results["sinks"].append({
                    "line": i,
                    "sink_type": sink_type,
                    "code": line.strip(),
                    "pattern": sink_pattern,
                })

                # Variable-aware path: tainted var appears in sink line
                for var_name, info in tainted_vars.items():
                    if _var_in_line(var_name, line):
                        results["potential_paths"].append({
                            "source_line": info["source_line"],
                            "source_code": info["source_code"],
                            "tainted_var": var_name,
                            "sink_line": i,
                            "sink_type": sink_type,
                            "sink_code": line.strip(),
                            "confidence": "likely",
                            "note": "Variable-tracking: tainted variable flows to sink",
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
    elif language in ("javascript", "typescript", "php", "ruby", "csharp"):
        results = analyze_with_variable_tracking(content, file_path, language)
    elif language == "go":
        try:
            from scripts.taint_go import analyze_file_go
            return analyze_file_go(file_path)
        except ImportError:
            results = analyze_with_patterns(content, file_path, language)
    elif language == "java":
        try:
            from scripts.taint_java import analyze_file_java
            return analyze_file_java(file_path)
        except ImportError:
            results = analyze_with_patterns(content, file_path, language)
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
