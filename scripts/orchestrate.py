#!/usr/bin/env python3
"""
Sub-skill orchestration helper — groups candidates by analysis phase
and emits self-contained JSON payloads for agent consumption.

Usage:
  python3 scripts/orchestrate.py --phase taint [--run-id <id>] [--max-findings 20]
  python3 scripts/orchestrate.py --list-phases

Each phase corresponds to a sub-skill and a subset of findings.
The output JSON is self-contained — agent doesn't need to re-read sub-skills from disk.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from scripts.utils.db import initialize_database, get_findings, get_latest_run

WORKSPACE = Path(__file__).parent.parent / "workspace"
SUBSKILLS_DIR = Path(__file__).parent.parent / "sub-skills"

# Phase → sub-skill file → vuln types to include
PHASES = {
    "taint": {
        "sub_skill": "taint-analyzer.md",
        "vuln_types": ["sqli", "cmdi", "path_traversal", "ssti", "ssrf", "xss", "deserialization", "ldap", "xxe"],
        "description": "Verify taint paths: source→propagator→sink. Check if user data actually reaches the sink.",
    },
    "auth": {
        "sub_skill": "auth-reviewer.md",
        "vuln_types": ["auth_bypass", "idor", "missing_auth", "jwt", "session"],
        "description": "Review authentication and authorization: missing checks, IDOR, JWT weaknesses.",
    },
    "input-validation": {
        "sub_skill": "input-validator.md",
        "vuln_types": ["xss", "open_redirect", "proto_pollution", "nosql_injection"],
        "description": "Check input validation at entry points: sanitization, allowlists, type enforcement.",
    },
    "crypto": {
        "sub_skill": "crypto-reviewer.md",
        "vuln_types": ["weak_crypto", "insecure_random", "hardcoded_secret", "weak_hash"],
        "description": "Review cryptographic weaknesses: weak algorithms, hardcoded keys, insecure random.",
    },
    "dependencies": {
        "sub_skill": "dependency-analyzer.md",
        "vuln_types": ["dependency_cve"],
        "description": "Verify dependency CVEs: confirm versions, check if the vulnerable code path is reachable.",
    },
    "secrets": {
        "sub_skill": "secrets-scanner.md",
        "vuln_types": ["secret", "high_entropy_string", "pem_block"],
        "description": "Review detected secrets: confirm they are real credentials, not test data.",
    },
    "iac": {
        "sub_skill": "iac-security-reviewer.md",
        "vuln_types": ["iac_misconfiguration", "container_security", "k8s_security", "terraform_security"],
        "description": "Review IaC findings: Dockerfile, Terraform, K8s manifests, GitHub Actions.",
    },
    "business-logic": {
        "sub_skill": "business-logic-analyzer.md",
        "vuln_types": ["race_condition", "toctou", "logic_flaw", "mass_assignment"],
        "description": "Review business logic: race conditions, TOCTOU, mass assignment, logic bypasses.",
    },
}


def load_sub_skill_prompt(sub_skill_name: str) -> str:
    """Load the sub-skill prompt text (first 3000 chars for context)."""
    path = SUBSKILLS_DIR / sub_skill_name
    if path.exists():
        text = path.read_text()
        return text[:3000] + ("...(truncated)" if len(text) > 3000 else "")
    return f"[Sub-skill not found: {sub_skill_name}]"


def get_code_excerpt(file_path: str, line_start: int, context: int = 5) -> str:
    """Get code snippet with context lines around the finding."""
    try:
        p = Path(file_path)
        if not p.exists():
            return ""
        lines = p.read_text(errors="replace").splitlines()
        start = max(0, line_start - context - 1)
        end = min(len(lines), line_start + context)
        excerpt_lines = []
        for i, line in enumerate(lines[start:end], start=start + 1):
            marker = ">>> " if i == line_start else "    "
            excerpt_lines.append(f"{marker}{i:4d}: {line}")
        return "\n".join(excerpt_lines)
    except OSError:
        return ""


def build_phase_payload(phase: str, findings: list, run_info: dict) -> dict:
    """Build the self-contained JSON payload for an agent phase."""
    phase_config = PHASES[phase]

    # Filter findings for this phase
    vuln_types = phase_config["vuln_types"]
    phase_findings = [
        f for f in findings
        if any(vt in (f.get("vuln_type") or "") for vt in vuln_types)
           or any(vt in (f.get("title") or "").lower() for vt in vuln_types)
    ]

    # Build code excerpts for each finding
    excerpts = {}
    for f in phase_findings:
        fp = f.get("file_path", "")
        ln = f.get("line_start") or 1
        key = f"{fp}:{ln}"
        if key not in excerpts and fp:
            excerpts[key] = get_code_excerpt(fp, ln)

    return {
        "phase": phase,
        "description": phase_config["description"],
        "sub_skill_name": phase_config["sub_skill"],
        "sub_skill_prompt": load_sub_skill_prompt(phase_config["sub_skill"]),
        "run_info": run_info,
        "finding_count": len(phase_findings),
        "findings": [
            {
                "id": f.get("id"),
                "title": f.get("title"),
                "vuln_type": f.get("vuln_type"),
                "severity": f.get("severity"),
                "confidence": f.get("confidence"),
                "file_path": f.get("file_path"),
                "line_start": f.get("line_start"),
                "cwe": f.get("cwe"),
                "description": f.get("description"),
                "taint_source": f.get("taint_source"),
                "taint_sink": f.get("taint_sink"),
                "code_snippet": f.get("code_snippet"),
                "taint_path": f.get("taint_path"),
            }
            for f in phase_findings
        ],
        "code_excerpts": excerpts,
        "instructions": (
            f"Review the {len(phase_findings)} findings below for the '{phase}' phase. "
            f"For each finding: (1) read the code excerpt, (2) verify the vulnerability is real, "
            f"(3) set confidence to 'confirmed', 'likely', or 'false_positive'. "
            f"Return a JSON list: [{{'id': ..., 'confidence': ..., 'status': ..., 'notes': ...}}]"
        ),
    }


def main():
    parser = argparse.ArgumentParser(description="Sub-skill orchestration helper")
    parser.add_argument("--phase", choices=list(PHASES.keys()), help="Analysis phase to generate payload for")
    parser.add_argument("--list-phases", action="store_true", help="List available phases")
    parser.add_argument("--run-id", help="Specific run ID (default: latest)")
    parser.add_argument("--max-findings", type=int, default=50, help="Max findings per phase")
    parser.add_argument("--output", help="Output file (default: stdout)")
    args = parser.parse_args()

    if args.list_phases:
        print("Available analysis phases:")
        for name, config in PHASES.items():
            print(f"  {name:<20} — {config['description'][:60]}")
        return

    if not args.phase:
        parser.print_help()
        return

    db_path = WORKSPACE / "scan_state.db"
    if not db_path.exists():
        print(f"Error: no scan database found at {db_path}", file=sys.stderr)
        print("Run: python3 scripts/scan.py --path <dir> first", file=sys.stderr)
        sys.exit(1)

    conn = initialize_database()

    run = get_latest_run(conn) if not args.run_id else conn.execute(
        "SELECT * FROM scan_runs WHERE id = ?", (args.run_id,)
    ).fetchone()

    if not run:
        print("Error: no scan run found", file=sys.stderr)
        sys.exit(1)

    findings = get_findings(conn, run_id=run["id"])
    findings = findings[:args.max_findings]

    run_info = {
        "id": run["id"],
        "path": run["path"],
        "started_at": run["timestamp"],
        "total_files": run["total_files"],
        "candidate_count": run["candidate_count"],
    }

    payload = build_phase_payload(args.phase, findings, run_info)

    output_str = json.dumps(payload, indent=2, default=str)

    if args.output:
        Path(args.output).write_text(output_str)
        print(f"Payload written to {args.output} ({len(payload['findings'])} findings)", file=sys.stderr)
    else:
        print(output_str)


if __name__ == "__main__":
    main()
