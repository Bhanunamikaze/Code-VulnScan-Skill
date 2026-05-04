#!/usr/bin/env python3
"""Go taint analysis via regex + variable tracking."""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

# ── Go source patterns ────────────────────────────────────────────────────────

GO_SOURCES = {
    "net_http": [
        r"r\.URL\.Query\s*\(\s*\)\.Get\s*\(",
        r"r\.FormValue\s*\(",
        r"r\.Form\s*\[",
        r"r\.PostFormValue\s*\(",
        r"r\.Header\.Get\s*\(",
        r"r\.Body\b",
        r"r\.URL\.Path\b",
        r"r\.URL\.RawQuery\b",
        r"ioutil\.ReadAll\s*\(\s*r\.Body",
        r"io\.ReadAll\s*\(\s*r\.Body",
    ],
    "gin": [
        r"c\.Query\s*\(",
        r"c\.Param\s*\(",
        r"c\.PostForm\s*\(",
        r"c\.GetHeader\s*\(",
        r"c\.Cookie\s*\(",
        r"c\.ShouldBindJSON\s*\(",
        r"c\.BindJSON\s*\(",
    ],
    "echo": [
        r"ctx\.QueryParam\s*\(",
        r"ctx\.Param\s*\(",
        r"ctx\.FormValue\s*\(",
        r"ctx\.Request\s*\(\s*\)",
    ],
    "fiber": [
        r"c\.Query\s*\(",
        r"c\.Params\s*\(",
        r"c\.Body\s*\(\s*\)",
    ],
    "generic": [
        r"os\.Args\b",
        r"os\.Getenv\s*\(",
        r"flag\.String\s*\(",
        r"flag\.StringVar\s*\(",
    ],
}

# ── Go sink patterns ──────────────────────────────────────────────────────────

GO_SINKS = {
    "sqli": [
        (r"db\.Query\s*\(\s*fmt\.Sprintf", "SQL with fmt.Sprintf interpolation"),
        (r"db\.Exec\s*\(\s*fmt\.Sprintf", "SQL exec with fmt.Sprintf"),
        (r"db\.QueryRow\s*\(\s*fmt\.Sprintf", "SQL queryrow with fmt.Sprintf"),
        (r"db\.Query\s*\(\s*\"[^\"]*\"\s*\+", "SQL with string concatenation"),
        (r"db\.Exec\s*\(\s*\"[^\"]*\"\s*\+", "SQL exec with string concatenation"),
        (r"gorm\.Raw\s*\(\s*fmt\.Sprintf", "GORM raw query with fmt.Sprintf"),
    ],
    "cmdi": [
        (r"exec\.Command\s*\(\s*[^,\n]+,\s*[^,\n]*\buser", "exec.Command with user input"),
        (r"exec\.Command\s*\(\s*\"sh\"\s*,\s*\"-c\"", "exec.Command with shell -c"),
        (r"exec\.CommandContext\s*\(", "exec.CommandContext"),
    ],
    "ssrf": [
        (r"http\.Get\s*\(", "http.Get with user URL"),
        (r"http\.Post\s*\(", "http.Post with user URL"),
        (r"http\.NewRequest\s*\(", "http.NewRequest with user URL"),
        (r"client\.Do\s*\(", "HTTP client.Do"),
    ],
    "path_traversal": [
        (r"os\.Open\s*\(", "os.Open with user path"),
        (r"os\.ReadFile\s*\(", "os.ReadFile with user path"),
        (r"ioutil\.ReadFile\s*\(", "ioutil.ReadFile with user path"),
        (r"os\.Create\s*\(", "os.Create with user path"),
        (r"filepath\.Join\s*\(", "filepath.Join with user path"),
    ],
    "xss": [
        (r"fmt\.Fprintf\s*\(\s*w", "fmt.Fprintf to ResponseWriter"),
        (r"w\.Write\s*\(", "ResponseWriter.Write with user data"),
        (r"template\.HTML\s*\(", "template.HTML unsafe conversion"),
        (r"template\.JS\s*\(", "template.JS unsafe conversion"),
    ],
    "ssti": [
        (r"text/template.*Parse\s*\(", "text/template Parse (unsafe, no auto-escape)"),
        (r"t\.Execute\s*\(", "template Execute with user data"),
    ],
}

# ── Go sanitizer patterns ─────────────────────────────────────────────────────

GO_SANITIZERS = {
    "sqli": [
        r"db\.Query\s*\(\s*\"[^\"]+\?\s*[^\"]+\"",   # ? placeholder
        r"db\.Query\s*\(\s*\"[^\"]+\$[0-9]+",         # $1 placeholder
        r"\.Prepare\s*\(",                              # prepared statement
    ],
    "xss": [
        r"html/template",           # auto-escaping template
        r"html\.EscapeString\s*\(",
        r"url\.QueryEscape\s*\(",
    ],
    "path_traversal": [
        r"filepath\.Clean\s*\(",
        r"strings\.HasPrefix\s*\(",  # combined with clean
    ],
    "ssrf": [
        r"url\.Parse\s*\(",          # URL validation
        r"net\.LookupHost\s*\(",     # host validation
    ],
}

# ── ORM safe patterns ─────────────────────────────────────────────────────────

GO_ORM_SAFE = [
    r"db\.Query\s*\(\s*\"[^\"]+\?\s*\"",    # ? placeholder in literal
    r"gorm\.Where\s*\(\s*\"[^\"]+\?\s*\"",  # GORM ? placeholder
    r"\.First\s*\(&",                         # GORM First (no raw SQL)
    r"\.Find\s*\(&",                          # GORM Find (no raw SQL)
    r"\.Create\s*\(&",                        # GORM Create (no raw SQL)
]

# ── Variable declaration regexes ──────────────────────────────────────────────

# Matches: varName := <rhs>  OR  var varName Type = <rhs>
_GO_ASSIGN_RE = re.compile(
    r"(?:(\w+)\s*:=\s*(.+))|(?:var\s+(\w+)\s+\w+\s*=\s*(.+))"
)

_DANGEROUS_IMPORTS = {
    "database/sql",
    "os/exec",
    "net/http",
    "text/template",
    "html/template",
    "io/ioutil",
    "os",
    "path/filepath",
}


def _is_source_line(line: str) -> tuple:
    """Return (source_type, pattern) if line matches any Go source, else (None, None)."""
    for src_type, patterns in GO_SOURCES.items():
        for pattern in patterns:
            if re.search(pattern, line):
                return src_type, pattern
    return None, None


def _is_sink_line(line: str) -> list:
    """Return list of (sink_type, sink_name, pattern) for sinks found in this line."""
    matches = []
    for sink_type, sink_list in GO_SINKS.items():
        for pattern, sink_name in sink_list:
            if re.search(pattern, line):
                matches.append((sink_type, sink_name, pattern))
    return matches


def _matches_orm_safe(line: str) -> bool:
    """Return True if line matches a Go ORM-safe pattern."""
    for pattern in GO_ORM_SAFE:
        if re.search(pattern, line):
            return True
    return False


def _has_sanitizer_in_block(lines: list, start: int, end: int, sink_type: str) -> bool:
    """Check if a sanitizer for sink_type appears between start and end (0-based indices)."""
    sanitizer_patterns = GO_SANITIZERS.get(sink_type, [])
    for idx in range(max(0, start), min(end + 1, len(lines))):
        for pattern in sanitizer_patterns:
            if re.search(pattern, lines[idx]):
                return True
    return False


def _var_in_line(var_name: str, line: str) -> bool:
    """Return True if var_name appears as a word boundary in line."""
    return bool(re.search(r'\b' + re.escape(var_name) + r'\b', line))


def analyze_go(content: str, file_path: str) -> dict:
    """Line-by-line Go taint analysis with variable tracking."""
    results = {"sources": [], "sinks": [], "potential_paths": []}
    lines = content.splitlines()

    # tainted_vars: var_name -> {"source_line": int, "source_code": str, "source_type": str}
    tainted_vars: dict = {}

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()

        # ── Step 1: Detect variable declarations / assignments ─────────────────
        assign_match = _GO_ASSIGN_RE.search(line)
        if assign_match:
            # Short declaration: group(1) = name, group(2) = rhs
            # Var declaration:   group(3) = name, group(4) = rhs
            var_name = assign_match.group(1) or assign_match.group(3)
            rhs = assign_match.group(2) or assign_match.group(4) or ""

            if var_name and rhs:
                rhs_src_type, _ = _is_source_line(rhs)
                if rhs_src_type:
                    tainted_vars[var_name] = {
                        "source_line": i,
                        "source_code": stripped,
                        "source_type": rhs_src_type,
                    }
                    if not any(s["line"] == i and s.get("variable") == var_name for s in results["sources"]):
                        results["sources"].append({
                            "line": i,
                            "variable": var_name,
                            "source_type": rhs_src_type,
                            "code": stripped,
                        })

                # Propagate taint: if RHS references an already-tainted variable
                for existing_var, info in list(tainted_vars.items()):
                    if _var_in_line(existing_var, rhs) and var_name not in tainted_vars:
                        tainted_vars[var_name] = {
                            "source_line": info["source_line"],
                            "source_code": info["source_code"],
                            "source_type": info["source_type"],
                        }
                        break

        # Record bare source appearances (no assignment captured)
        src_type, src_pattern = _is_source_line(line)
        if src_type and not any(s["line"] == i for s in results["sources"]):
            results["sources"].append({
                "line": i,
                "variable": None,
                "source_type": src_type,
                "code": stripped,
            })

        # ── Step 2: Detect sinks ───────────────────────────────────────────────
        sink_matches = _is_sink_line(line)
        for sink_type, sink_name, sink_pattern in sink_matches:

            # Skip ORM-safe patterns (parameterized queries)
            if _matches_orm_safe(line):
                continue

            results["sinks"].append({
                "line": i,
                "sink_type": sink_type,
                "sink_name": sink_name,
                "code": stripped,
            })

            # ── Step 3: Match tainted variables to sinks ───────────────────────
            matched_via_var = False
            for var_name, info in tainted_vars.items():
                if _var_in_line(var_name, line):
                    src_line_idx = info["source_line"] - 1  # 0-based
                    sink_line_idx = i - 1                    # 0-based

                    # Check sanitizers in function body (between source and sink)
                    has_sanitizer = _has_sanitizer_in_block(
                        lines, src_line_idx, sink_line_idx, sink_type
                    )
                    confidence = "possible" if has_sanitizer else "likely"

                    results["potential_paths"].append({
                        "source_line": info["source_line"],
                        "source_type": info["source_type"],
                        "source_code": info["source_code"],
                        "tainted_var": var_name,
                        "sink_line": i,
                        "sink_type": sink_type,
                        "sink_name": sink_name,
                        "sink_code": stripped,
                        "confidence": confidence,
                        "note": (
                            "Sanitizer detected between source and sink — verify effectiveness"
                            if has_sanitizer
                            else "Variable-tracking: tainted variable flows to sink"
                        ),
                    })
                    matched_via_var = True


    return results


def analyze_go_imports(content: str) -> dict:
    """Extract import information and flag dangerous packages."""
    imports = []
    uses_text_template = False
    uses_exec = False

    # Match single import: import "pkg"
    single_import_re = re.compile(r'^\s*import\s+"([^"]+)"')
    # Match import block: import ( ... )
    import_block_re = re.compile(r'import\s*\(([^)]+)\)', re.DOTALL)

    for m in single_import_re.finditer(content):
        pkg = m.group(1).strip()
        imports.append(pkg)

    for block_match in import_block_re.finditer(content):
        block = block_match.group(1)
        for line in block.splitlines():
            line = line.strip().strip('"')
            # Handle aliased imports: alias "pkg"
            parts = line.split()
            if parts:
                pkg = parts[-1].strip('"')
                if pkg:
                    imports.append(pkg)

    # Deduplicate while preserving order
    seen = set()
    unique_imports = []
    for pkg in imports:
        if pkg not in seen:
            seen.add(pkg)
            unique_imports.append(pkg)

    uses_text_template = "text/template" in seen
    uses_exec = "os/exec" in seen

    return {
        "imports": unique_imports,
        "uses_text_template": uses_text_template,
        "uses_exec": uses_exec,
    }


def analyze_file_go(file_path: str) -> dict:
    """Analyze a Go file for taint paths. Returns the standard dict format."""
    content = Path(file_path).read_text(errors="replace")
    result = analyze_go(content, file_path)
    import_info = analyze_go_imports(content)
    result["imports"] = import_info
    result["file"] = file_path
    result["language"] = "go"
    result["total_sources"] = len(result["sources"])
    result["total_sinks"] = len(result["sinks"])
    result["total_potential_paths"] = len(result["potential_paths"])
    return result
