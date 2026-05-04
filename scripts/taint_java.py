#!/usr/bin/env python3
"""Java taint analysis via tree-sitter (with regex fallback)."""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

# ── Java source patterns (request input) ─────────────────────────────────────

JAVA_SOURCES = {
    "spring_mvc": [
        r"@RequestParam\b",
        r"@PathVariable\b",
        r"@RequestBody\b",
        r"@RequestHeader\b",
        r"\.getParameter\s*\(",
        r"\.getQueryString\s*\(",
        r"\.getHeader\s*\(",
        r"\.getInputStream\s*\(",
        r"\.getCookies\s*\(",
    ],
    "servlet": [
        r"request\.getParameter\s*\(",
        r"request\.getParameterValues\s*\(",
        r"request\.getAttribute\s*\(",
        r"request\.getInputStream\s*\(",
        r"request\.getReader\s*\(",
    ],
    "generic": [
        r"System\.in\b",
        r"args\[",
        r"System\.getenv\s*\(",
        r"System\.getProperty\s*\(",
    ],
}

# ── Java sink patterns ────────────────────────────────────────────────────────

JAVA_SINKS = {
    "sqli": [
        (r"Statement\.(executeQuery|executeUpdate|execute)\s*\(", "SQL Statement execution"),
        (r"\.prepareStatement\s*\(\s*\".*\+", "PreparedStatement with concatenation"),
        (r"EntityManager\.createNativeQuery\s*\(", "JPA native query"),
        (r"jdbcTemplate\.execute\s*\(\s*\"", "JdbcTemplate with string query"),
        (r"session\.createSQLQuery\s*\(", "Hibernate createSQLQuery"),
    ],
    "cmdi": [
        (r"Runtime\.getRuntime\s*\(\s*\)\.exec\s*\(", "Runtime.exec()"),
        (r"new\s+ProcessBuilder\s*\(", "ProcessBuilder"),
        (r"ProcessBuilder\.command\s*\(", "ProcessBuilder.command()"),
    ],
    "path_traversal": [
        (r"new\s+File\s*\(", "File instantiation with user input"),
        (r"Files\.(readAllBytes|write|copy|move)\s*\(", "Files I/O operation"),
        (r"new\s+FileInputStream\s*\(", "FileInputStream with user input"),
    ],
    "xxe": [
        (r"XMLDecoder\s*\(", "XMLDecoder (always unsafe)"),
        (r"DocumentBuilder\.parse\s*\(", "DocumentBuilder.parse without XXE protection"),
    ],
    "ssti": [
        (r"new\s+Template\s*\(", "FreeMarker Template instantiation"),
        (r"template\.process\s*\(", "FreeMarker template.process()"),
        (r"ScriptEngine\.eval\s*\(", "ScriptEngine eval with user data"),
    ],
    "ldap": [
        (r"dirContext\.search\s*\(", "LDAP dirContext.search"),
        (r"ldapTemplate\.search\s*\(", "LDAP template search"),
    ],
    "deserialization": [
        (r"ObjectInputStream\s*\(", "Java object deserialization"),
        (r"readObject\s*\(\s*\)", "readObject() deserialization"),
    ],
    "ssrf": [
        (r"new\s+URL\s*\(", "URL with user-controlled string"),
        (r"HttpClient\.execute\s*\(", "HttpClient execute with user URL"),
        (r"RestTemplate\.(get|post|exchange)ForObject\s*\(", "RestTemplate HTTP call"),
    ],
    "xss": [
        (r"response\.getWriter\s*\(\s*\)\.(?:print|write)\s*\(", "HttpServletResponse write"),
        (r"PrintWriter\.print\s*\(", "PrintWriter print with user data"),
    ],
}

# ── Java sanitizer patterns ───────────────────────────────────────────────────

JAVA_SANITIZERS = {
    "sqli": [
        r"PreparedStatement\.set(?:String|Int|Long|Date|Boolean)\s*\(",
        r"\.setParameter\s*\(",        # Hibernate
        r"@Query\s*\(",                # Spring Data named params
        r"ESAPI\.encoder\s*\(",
    ],
    "cmdi": [
        r"ProcessBuilder\s*\(\s*Arrays\.",  # ProcessBuilder with list (no shell)
        r"ESAPI\.encoder\s*\(\s*\)\.encodeForOS",
    ],
    "xss": [
        r"ESAPI\.encoder\s*\(\s*\)\.encodeForHTML",
        r"Jsoup\.clean\s*\(",
        r"StringEscapeUtils\.escapeHtml",
        r"HtmlUtils\.htmlEscape\s*\(",
    ],
    "path_traversal": [
        r"Paths\.get\s*\(.+\)\.normalize\s*\(\s*\)",
        r"\.toRealPath\s*\(\s*\)",
    ],
}

# ── ORM safe patterns ─────────────────────────────────────────────────────────

JAVA_ORM_SAFE = [
    r"PreparedStatement\b",
    r"@NamedQuery\b",
    r"@Query\s*\([^)]*:[\w]+\b",   # named params
    r"CriteriaBuilder\b",
    r"CriteriaQuery\b",
    r"Specification\b",
    r"JpaRepository\b",
    r"\.findById\s*\(",
    r"\.findAll\s*\(",
    r"\.save\s*\(",
]

# ── Variable assignment regex ─────────────────────────────────────────────────

_JAVA_ASSIGN_RE = re.compile(r"\b(\w+)\s+(\w+)\s*=\s*(.+)")


def _is_source_line(line: str) -> tuple:
    """Return (source_type, pattern) if line matches a source, else (None, None)."""
    for src_type, patterns in JAVA_SOURCES.items():
        for pattern in patterns:
            if re.search(pattern, line):
                return src_type, pattern
    return None, None


def _is_sink_line(line: str) -> list:
    """Return list of (sink_type, sink_name) matches for sinks in this line."""
    matches = []
    for sink_type, sink_list in JAVA_SINKS.items():
        for pattern, sink_name in sink_list:
            if re.search(pattern, line):
                matches.append((sink_type, sink_name, pattern))
    return matches


def _has_sanitizer(lines: list, start: int, end: int, sink_type: str) -> bool:
    """Check if any sanitizer for sink_type appears between start and end line indices."""
    sanitizer_patterns = JAVA_SANITIZERS.get(sink_type, [])
    for idx in range(start, min(end + 1, len(lines))):
        for pattern in sanitizer_patterns:
            if re.search(pattern, lines[idx]):
                return True
    return False


def _matches_orm_safe(line: str) -> bool:
    """Return True if the line matches an ORM-safe pattern."""
    for pattern in JAVA_ORM_SAFE:
        if re.search(pattern, line):
            return True
    return False


def _var_in_line(var_name: str, line: str) -> bool:
    """Return True if var_name appears as a word boundary in line."""
    return bool(re.search(r'\b' + re.escape(var_name) + r'\b', line))


def analyze_java(content: str, file_path: str) -> dict:
    """Line-by-line Java taint analysis with variable tracking."""
    results = {"sources": [], "sinks": [], "potential_paths": []}
    lines = content.splitlines()

    # tainted_vars: var_name -> {"source_line": int, "source_code": str, "source_type": str}
    tainted_vars: dict = {}

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()

        # ── Step 1: Detect source appearances and variable assignments ────────
        src_type, src_pattern = _is_source_line(line)

        # Check for typed variable assignment: TypeName varName = <rhs>
        assign_match = _JAVA_ASSIGN_RE.search(line)
        if assign_match:
            type_name = assign_match.group(1)
            var_name = assign_match.group(2)
            rhs = assign_match.group(3)

            # If RHS contains a source pattern, taint the variable
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

        # Record bare source appearances (no assignment capture)
        if src_type and not any(s["line"] == i for s in results["sources"]):
            results["sources"].append({
                "line": i,
                "variable": None,
                "source_type": src_type,
                "code": stripped,
            })

        # ── Step 2: Detect sinks ──────────────────────────────────────────────
        sink_matches = _is_sink_line(line)
        for sink_type, sink_name, sink_pattern in sink_matches:

            # Check ORM safe patterns — if sink line matches a safe ORM pattern
            # and the usage looks like a parameter (not string concatenation), skip
            if _matches_orm_safe(line) and "+" not in line:
                continue

            results["sinks"].append({
                "line": i,
                "sink_type": sink_type,
                "sink_name": sink_name,
                "code": stripped,
            })

            # ── Step 3: Match tainted variables to sinks ──────────────────────
            matched_via_var = False
            for var_name, info in tainted_vars.items():
                if _var_in_line(var_name, line):
                    src_line_idx = info["source_line"] - 1  # 0-based
                    sink_line_idx = i - 1                   # 0-based

                    # Check for sanitizers between source and sink
                    has_sanitizer = _has_sanitizer(lines, src_line_idx, sink_line_idx, sink_type)
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

            # Fallback: proximity matching if no variable path found
            if not matched_via_var:
                nearby_sources = [s for s in results["sources"] if abs(s["line"] - i) <= 20]
                for src in nearby_sources:
                    results["potential_paths"].append({
                        "source_line": src["line"],
                        "source_type": src.get("source_type"),
                        "source_code": src["code"],
                        "tainted_var": src.get("variable"),
                        "sink_line": i,
                        "sink_type": sink_type,
                        "sink_name": sink_name,
                        "sink_code": stripped,
                        "confidence": "possible",
                        "note": "Pattern proximity — requires manual verification",
                    })

    return results


def analyze_java_annotations(content: str) -> list:
    """Scan for dangerous Java annotation combinations."""
    findings = []
    lines = content.splitlines()

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()

        # @CrossOrigin without origins restriction
        if re.search(r"@CrossOrigin\b", stripped):
            if not re.search(r"origins\s*=", stripped):
                findings.append({
                    "line": i,
                    "annotation": "@CrossOrigin",
                    "severity": "medium",
                    "issue": "CORS: @CrossOrigin without origins restriction allows any origin",
                    "code": stripped,
                })

        # @RequestMapping without method restriction
        if re.search(r"@RequestMapping\b", stripped):
            if not re.search(r"method\s*=", stripped):
                findings.append({
                    "line": i,
                    "annotation": "@RequestMapping",
                    "severity": "medium",
                    "issue": "@RequestMapping without method restriction accepts all HTTP methods",
                    "code": stripped,
                })

    return findings


def analyze_file_java(file_path: str) -> dict:
    """Analyze a Java file for taint paths. Returns the standard dict format."""
    content = Path(file_path).read_text(errors="replace")
    result = analyze_java(content, file_path)
    annotation_findings = analyze_java_annotations(content)
    result["annotation_findings"] = annotation_findings
    result["file"] = file_path
    result["language"] = "java"
    result["total_sources"] = len(result["sources"])
    result["total_sinks"] = len(result["sinks"])
    result["total_potential_paths"] = len(result["potential_paths"])
    return result
