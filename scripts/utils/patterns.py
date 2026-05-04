"""Vulnerability pattern definitions — sources, sinks, sanitizers per language."""

import json
import re
from pathlib import Path

PATTERNS_DIR = Path(__file__).parent.parent.parent / "resources" / "patterns"


def load_patterns(language: str) -> dict:
    """Load patterns for a given language, falling back to generic."""
    file = PATTERNS_DIR / f"{language}_patterns.json"
    if not file.exists():
        file = PATTERNS_DIR / "generic_patterns.json"
    if not file.exists():
        return {}
    with open(file) as f:
        return json.load(f)


def match_patterns(content: str, patterns: list) -> list:
    """Return list of (line_number, line_content, pattern_id) for each match."""
    lines = content.splitlines()
    matches = []
    for pattern_def in patterns:
        regex = pattern_def.get("regex", "")
        pid = pattern_def.get("id", "unknown")
        vuln_type = pattern_def.get("vuln_type", "unknown")
        confidence = pattern_def.get("confidence", "possible")
        description = pattern_def.get("description", "")
        try:
            compiled = re.compile(regex, re.IGNORECASE)
        except re.error:
            continue
        for i, line in enumerate(lines, start=1):
            m = compiled.search(line)
            if m:
                matches.append({
                    "line": i,
                    "content": line.strip(),
                    "pattern_id": pid,
                    "vuln_type": vuln_type,
                    "confidence": confidence,
                    "description": description,
                    "match": m.group(0),
                })
    return matches


def scan_file_for_candidates(file_path, content: str, language: str) -> list:
    """Run all patterns for a language against a file's content."""
    patterns_data = load_patterns(language)
    all_patterns = []
    for category, plist in patterns_data.items():
        if isinstance(plist, list):
            all_patterns.extend(plist)

    matches = match_patterns(content, all_patterns)
    candidates = []
    for m in matches:
        candidates.append({
            "file_path": str(file_path),
            "line_start": m["line"],
            "language": language,
            "vuln_type": m["vuln_type"],
            "confidence": m["confidence"],
            "title": m["description"] or f"Potential {m['vuln_type']} — {m['pattern_id']}",
            "code_snippet": m["content"],
            "pattern_id": m["pattern_id"],
            "status": "candidate",
        })
    return candidates
