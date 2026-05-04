#!/usr/bin/env python3
"""
Code-VulnScan — ReDoS (Regular Expression Denial of Service) detector.

Detects regex patterns susceptible to catastrophic backtracking by analysing
their structural complexity. Supports Python, JavaScript, Java, PHP, Ruby, Go.

Usage:
  python3 scripts/regex_analyzer.py --path <dir> [--output <file>]
"""

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from scripts.utils.files import enumerate_files, read_file

# Language-specific patterns for locating regex literals and compile calls
REGEX_EXTRACTORS = {
    "python": [
        # re.compile(r'...')  or re.compile('...')
        (r're\.(compile|search|match|fullmatch|findall|finditer|sub|subn|split)\s*\(\s*(?:r|b)?["\']([^"\'\\]|\\.)+["\']', 2),
    ],
    "javascript": [
        # /pattern/flags or new RegExp('pattern')
        (r'(?<![/\*])/([^/\n\\]|\\.)+/[gimsuy]*', 1),
        (r'new\s+RegExp\s*\(\s*["\']([^"\'\\]|\\.)+["\']', 1),
    ],
    "typescript": [
        (r'(?<![/\*])/([^/\n\\]|\\.)+/[gimsuy]*', 1),
        (r'new\s+RegExp\s*\(\s*["\']([^"\'\\]|\\.)+["\']', 1),
    ],
    "java": [
        (r'Pattern\.compile\s*\(\s*["\']([^"\'\\]|\\.)+["\']', 1),
        (r'\.matches\s*\(\s*["\']([^"\'\\]|\\.)+["\']', 1),
    ],
    "kotlin": [
        (r'Regex\s*\(\s*["\']([^"\'\\]|\\.)+["\']', 1),
        (r'Pattern\.compile\s*\(\s*["\']([^"\'\\]|\\.)+["\']', 1),
    ],
    "php": [
        (r'preg_(match|match_all|replace|split)\s*\(\s*["\']([^"\'\\]|\\.)+["\']', 1),
    ],
    "ruby": [
        (r'/([^/\n\\]|\\.)+/[imxo]*', 1),
        (r'Regexp\.new\s*\(\s*["\']([^"\'\\]|\\.)+["\']', 1),
    ],
    "go": [
        (r'regexp\.(Compile|MustCompile|Match|MatchString|QuoteMeta)\s*\(\s*`([^`]+)`', 2),
        (r'regexp\.(Compile|MustCompile|Match|MatchString)\s*\(\s*["\']([^"\'\\]|\\.)+["\']', 2),
    ],
    "csharp": [
        (r'new\s+Regex\s*\(\s*["\']([^"\'\\]|\\.)+["\']', 1),
        (r'Regex\.(IsMatch|Match|Matches|Replace|Split)\s*\(\s*\w+\s*,\s*["\']([^"\'\\]|\\.)+["\']', 2),
    ],
}


def extract_regex_literal(match_text: str) -> str:
    """Extract just the pattern string from a match."""
    # Find quoted string content
    m = re.search(r'["\']([^"\'\\]|\\.)*["\']', match_text)
    if m:
        s = m.group(0)
        return s[1:-1]
    # Regex literal /pattern/
    m = re.search(r'/(.+)/[gimsuy]*$', match_text)
    if m:
        return m.group(1)
    # Backtick (Go)
    m = re.search(r'`([^`]+)`', match_text)
    if m:
        return m.group(1)
    return match_text


# ── Complexity analysis ───────────────────────────────────────────────────────

def count_quantifiers(pattern: str) -> int:
    return len(re.findall(r'(?<!\\.)[*+?]|\{\d+,\d*\}', pattern))


def has_nested_quantifiers(pattern: str) -> bool:
    """Detect (A+)+ , (A*)* , (A+)* patterns — primary ReDoS indicator."""
    # Remove escaped chars first
    p = re.sub(r'\\.', 'X', pattern)
    # Look for group containing quantifier, followed by outer quantifier
    return bool(re.search(r'\([^)]*[*+]\)[*+?]|\([^)]*\{[^}]+\}\)[*+?]', p))


def has_alternation_with_common_prefix(pattern: str) -> bool:
    """Detect (a+|a+b) alternations that share prefix — exponential backtracking."""
    p = re.sub(r'\\.', 'X', pattern)
    alts = re.findall(r'\(([^)]+)\)', p)
    for alt in alts:
        parts = alt.split('|')
        if len(parts) < 2:
            continue
        # Check if parts share a common prefix character class or literal
        for i, part in enumerate(parts):
            for j, other in enumerate(parts):
                if i >= j:
                    continue
                if part and other and part[0] == other[0]:
                    return True
    return False


def has_overlapping_character_classes(pattern: str) -> bool:
    """Detect (.+)* or (\w+)+ patterns with greedy outer quantifier."""
    p = re.sub(r'\\.', 'X', pattern)
    return bool(re.search(r'\(\.[*+]\)[*+?]|\(\\w\+\)[*+?]|\(\\d\+\)[*+?]', p))


def estimate_complexity(pattern: str) -> str:
    """
    Estimate regex complexity.
    Returns: 'catastrophic' | 'exponential' | 'polynomial' | 'linear'
    """
    if has_nested_quantifiers(pattern):
        return "catastrophic"
    if has_alternation_with_common_prefix(pattern):
        return "exponential"
    if count_quantifiers(pattern) >= 3:
        return "polynomial"
    return "linear"


def is_anchored(pattern: str) -> bool:
    """Anchored patterns (^ ... $) are generally safe — no backtracking into the full string."""
    return pattern.startswith("^") and pattern.endswith("$")


def analyze_pattern(pattern: str) -> dict:
    complexity = estimate_complexity(pattern)
    anchored = is_anchored(pattern)
    severity = "info"

    if complexity == "catastrophic" and not anchored:
        severity = "high"
    elif complexity == "exponential" and not anchored:
        severity = "medium"
    elif complexity == "polynomial" and not anchored:
        severity = "low"

    return {
        "complexity": complexity,
        "anchored": anchored,
        "severity": severity,
        "nested_quantifiers": has_nested_quantifiers(pattern),
        "alt_common_prefix": has_alternation_with_common_prefix(pattern),
        "quantifier_count": count_quantifiers(pattern),
    }


# ── File scanning ─────────────────────────────────────────────────────────────

def scan_file_for_redos(file_path: Path, content: str, language: str) -> list:
    findings = []
    extractors = REGEX_EXTRACTORS.get(language, [])

    for extractor_pattern, _ in extractors:
        for m in re.finditer(extractor_pattern, content, re.MULTILINE):
            raw = m.group(0)
            regex_str = extract_regex_literal(raw)
            if not regex_str or len(regex_str) < 4:
                continue

            analysis = analyze_pattern(regex_str)
            if analysis["severity"] == "info":
                continue

            line_start = content[:m.start()].count("\n") + 1
            findings.append({
                "file_path": str(file_path),
                "line_start": line_start,
                "language": language,
                "pattern": regex_str[:120],
                "raw_match": raw[:200],
                "vuln_type": "redos",
                "severity": analysis["severity"],
                "complexity": analysis["complexity"],
                "anchored": analysis["anchored"],
                "nested_quantifiers": analysis["nested_quantifiers"],
                "alt_common_prefix": analysis["alt_common_prefix"],
                "quantifier_count": analysis["quantifier_count"],
                "description": _build_description(analysis, regex_str),
                "remediation": _build_remediation(analysis),
                "status": "candidate",
            })

    return findings


def _build_description(analysis: dict, pattern: str) -> str:
    parts = []
    if analysis["nested_quantifiers"]:
        parts.append("nested quantifiers (e.g. (A+)+) enable catastrophic backtracking")
    if analysis["alt_common_prefix"]:
        parts.append("alternation with common prefix enables exponential backtracking")
    if not parts:
        parts.append(f"high quantifier density ({analysis['quantifier_count']} quantifiers) may cause polynomial backtracking")
    anchored_note = " Pattern is anchored (lower risk)" if analysis["anchored"] else " Pattern is NOT anchored (higher risk on long inputs)"
    return f"ReDoS risk — {', '.join(parts)}.{anchored_note}"


def _build_remediation(analysis: dict) -> str:
    steps = [
        "1. Test with a crafted long input (e.g. 'a' * 50000) and measure execution time",
        "2. Rewrite using atomic groups or possessive quantifiers where supported",
        "3. Replace nested quantifiers with bounded alternatives: (a{1,100})+ instead of (a+)+",
        "4. Anchor the pattern (^...$) if possible to limit backtracking scope",
        "5. Use a linear-time regex engine (RE2 / re2j / Go regexp) which prohibit backtracking",
        "6. Apply input length validation before calling the regex",
    ]
    return "\n".join(steps)


def scan_for_redos(base_path: Path) -> dict:
    supported_langs = set(REGEX_EXTRACTORS.keys())
    files = enumerate_files(base_path, include_langs=list(supported_langs), include_config=False)

    all_findings = []
    files_scanned = 0

    for file_info in files:
        content = read_file(file_info["path"])
        if not content:
            continue
        findings = scan_file_for_redos(file_info["path"], content, file_info["language"])
        all_findings.extend(findings)
        files_scanned += 1

    all_findings.sort(key=lambda x: {"high": 0, "medium": 1, "low": 2}.get(x["severity"], 3))

    return {
        "files_scanned": files_scanned,
        "findings": all_findings,
        "summary": {
            "high": sum(1 for f in all_findings if f["severity"] == "high"),
            "medium": sum(1 for f in all_findings if f["severity"] == "medium"),
            "low": sum(1 for f in all_findings if f["severity"] == "low"),
        },
    }


def main():
    parser = argparse.ArgumentParser(description="Code-VulnScan ReDoS detector")
    parser.add_argument("--path", required=True, help="Path to scan")
    parser.add_argument("--output", help="Output JSON file")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    base = Path(args.path)
    if not base.exists():
        print(f"Error: path not found: {base}", file=sys.stderr)
        sys.exit(1)

    print(f"Scanning for ReDoS patterns in: {base}", file=sys.stderr)
    results = scan_for_redos(base)

    indent = 2 if args.pretty else None
    output_str = json.dumps(results, indent=indent)

    if args.output:
        Path(args.output).write_text(output_str)
        print(f"Results written to: {args.output}", file=sys.stderr)
    else:
        print(output_str)

    s = results["summary"]
    print(
        f"\nReDoS scan: {len(results['findings'])} patterns found in {results['files_scanned']} files "
        f"({s['high']} high, {s['medium']} medium, {s['low']} low)",
        file=sys.stderr,
    )

    for f in results["findings"][:15]:
        print(
            f"  [{f['severity'].upper():6}] {f['file_path']}:{f['line_start']} — "
            f"{f['complexity']} — {f['pattern'][:60]}",
            file=sys.stderr,
        )

    print("\nNote: verify each pattern by crafting a long matching input and timing execution", file=sys.stderr)


if __name__ == "__main__":
    main()
