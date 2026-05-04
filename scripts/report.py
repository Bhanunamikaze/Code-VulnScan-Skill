#!/usr/bin/env python3
"""
Report generator — produces Markdown, JSON, and SARIF reports from confirmed findings.

Usage:
  python3 scripts/report.py [--run-id <id>] [--format markdown|json|sarif|all] [--min-severity medium]
"""

import argparse
import json
import sys
import uuid
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from scripts.utils.db import initialize_database, get_findings, get_latest_run, list_runs

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
SEVERITY_EMOJI = {
    "critical": "[CRITICAL]",
    "high": "[HIGH]",
    "medium": "[MEDIUM]",
    "low": "[LOW]",
    "informational": "[INFO]",
}

WORKSPACE = Path(__file__).parent.parent / "workspace"


def get_run_and_findings(conn, run_id=None, min_severity="medium"):
    if run_id:
        run = conn.execute("SELECT * FROM scan_runs WHERE id = ?", (run_id,)).fetchone()
    else:
        run = get_latest_run(conn)

    if not run:
        print("Error: no scan run found.", file=sys.stderr)
        sys.exit(1)

    findings = get_findings(conn, run_id=run["id"],
                            status=["confirmed", "likely"],
                            min_severity=min_severity)
    return run, findings


def generate_markdown(run, findings) -> str:
    lines = []
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    sev_counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    lines.append("# Security Vulnerability Report — Code-VulnScan")
    lines.append(f"\n**Target:** `{run['path']}`")
    lines.append(f"**Scan ID:** `{run['id']}`")
    lines.append(f"**Generated:** {ts}")
    lines.append(f"**Tool:** Code-VulnScan v1.0.0\n")

    lines.append("---\n")
    lines.append("## Executive Summary\n")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in ["critical", "high", "medium", "low", "informational"]:
        count = sev_counts.get(sev, 0)
        if count > 0:
            lines.append(f"| **{sev.capitalize()}** | {count} |")
    lines.append(f"| **Total** | {len(findings)} |")
    lines.append("")

    if findings:
        top = findings[0]
        lines.append(f"\nMost critical issue: **{top['title']}** in `{top['file_path']}` "
                     f"(CVSS: {top['cvss_score'] or 'N/A'}). "
                     f"Immediate remediation required for all Critical and High findings.")
    lines.append("\n---\n")

    # Group by severity then category
    from collections import defaultdict
    by_sev = defaultdict(list)
    for f in findings:
        by_sev[f["severity"]].append(f)

    for sev in ["critical", "high", "medium", "low", "informational"]:
        sev_findings = by_sev.get(sev, [])
        if not sev_findings:
            continue

        lines.append(f"## {sev.capitalize()} Findings ({len(sev_findings)})\n")

        for i, f in enumerate(sev_findings, 1):
            label = SEVERITY_EMOJI.get(sev, f"[{sev.upper()}]")
            lines.append(f"### {label} {f['title']}\n")
            lines.append(f"**File:** `{f['file_path']}`:{f['line_start'] or '?'}")
            if f["cwe"]:
                lines.append(f"  \n**CWE:** {f['cwe']}")
            if f["owasp"]:
                lines.append(f"  \n**OWASP:** {f['owasp']}")
            if f["cvss_score"]:
                lines.append(f"  \n**CVSS:** {f['cvss_score']}" +
                             (f" (`{f['cvss_vector']}`)" if f["cvss_vector"] else ""))
            lines.append(f"  \n**Confidence:** {f['confidence'].capitalize() if f['confidence'] else 'N/A'}\n")

            if f["description"]:
                lines.append("#### Description\n")
                lines.append(f"{f['description']}\n")

            if f["code_snippet"]:
                lines.append("#### Evidence\n")
                lang = f.get("language") or ""
                lines.append(f"```{lang}")
                lines.append(f["code_snippet"])
                lines.append("```\n")

            if f["taint_path"]:
                lines.append("#### Taint Path\n")
                try:
                    path_steps = json.loads(f["taint_path"]) if isinstance(f["taint_path"], str) else f["taint_path"]
                    if isinstance(path_steps, list):
                        for j, step in enumerate(path_steps, 1):
                            lines.append(f"{j}. `{step}`")
                    else:
                        lines.append(f"`{f['taint_path']}`")
                except (json.JSONDecodeError, TypeError):
                    lines.append(f"`{f['taint_path']}`")
                lines.append("")

            if f["taint_source"] or f["taint_sink"]:
                if f["taint_source"]:
                    lines.append(f"**Source:** `{f['taint_source']}`  ")
                if f["taint_sink"]:
                    lines.append(f"**Sink:** `{f['taint_sink']}`\n")

            if f["remediation"]:
                lines.append("#### Remediation\n")
                lines.append(f"{f['remediation']}\n")

            lines.append("---\n")

    # Remediation checklist
    lines.append("## Remediation Priority Checklist\n")
    for sev in ["critical", "high", "medium"]:
        sev_findings = by_sev.get(sev, [])
        if sev_findings:
            lines.append(f"### {sev.capitalize()} — Fix Immediately\n")
            for f in sev_findings:
                lines.append(f"- [ ] {f['title']} — `{f['file_path']}`:{f['line_start'] or '?'}")
            lines.append("")

    lines.append("\n---")
    lines.append("*Report generated by [Code-VulnScan](https://github.com/Bhanunamikaze/Code-VulnScan-Skill)*")

    return "\n".join(lines)


def generate_json(run, findings) -> dict:
    return {
        "schema_version": "1.0.0",
        "tool": "Code-VulnScan",
        "scan_id": run["id"],
        "target": run["path"],
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "summary": {
            "critical": sum(1 for f in findings if f["severity"] == "critical"),
            "high": sum(1 for f in findings if f["severity"] == "high"),
            "medium": sum(1 for f in findings if f["severity"] == "medium"),
            "low": sum(1 for f in findings if f["severity"] == "low"),
            "total": len(findings),
        },
        "findings": [
            {
                "id": f["id"],
                "title": f["title"],
                "severity": f["severity"],
                "confidence": f["confidence"],
                "file": f["file_path"],
                "line_start": f["line_start"],
                "line_end": f["line_end"],
                "language": f["language"],
                "vuln_type": f["vuln_type"],
                "cwe": f["cwe"],
                "owasp": f["owasp"],
                "cvss_score": f["cvss_score"],
                "cvss_vector": f["cvss_vector"],
                "description": f["description"],
                "taint_source": f["taint_source"],
                "taint_sink": f["taint_sink"],
                "remediation": f["remediation"],
            }
            for f in findings
        ],
    }


def generate_sarif(run, findings) -> dict:
    rules = {}
    results = []

    for f in findings:
        rule_id = f["cwe"] or f["vuln_type"] or "UNKNOWN"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f["vuln_type"] or "vulnerability",
                "shortDescription": {"text": f["title"]},
                "fullDescription": {"text": f["description"] or f["title"]},
                "helpUri": f"https://cwe.mitre.org/data/definitions/{rule_id.replace('CWE-', '')}.html" if f["cwe"] else "",
                "properties": {
                    "tags": [f["vuln_type"] or "security"],
                    "security-severity": str(f["cvss_score"] or "5.0"),
                },
            }

        severity_map = {"critical": "error", "high": "error", "medium": "warning",
                        "low": "note", "informational": "note"}

        result = {
            "ruleId": rule_id,
            "level": severity_map.get(f["severity"], "warning"),
            "message": {"text": f["title"] + (f". {f['description']}" if f["description"] else "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f["file_path"].lstrip("/")},
                    "region": {
                        "startLine": f["line_start"] or 1,
                        "endLine": f["line_end"] or f["line_start"] or 1,
                    },
                }
            }],
            "fingerprints": {
                "0": str(uuid.uuid5(uuid.NAMESPACE_URL, f"{f['file_path']}:{f['line_start']}:{f['vuln_type']}"))
            },
        }

        if f["remediation"]:
            result["fixes"] = [{"description": {"text": f["remediation"]}}]

        results.append(result)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Code-VulnScan",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/Bhanunamikaze/Code-VulnScan-Skill",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "commandLine": f"vulnscan scan {run['path']}",
            }],
        }],
    }


def main():
    parser = argparse.ArgumentParser(description="Code-VulnScan report generator")
    parser.add_argument("--run-id", help="Specific run ID (default: latest)")
    parser.add_argument("--format", choices=["markdown", "json", "sarif", "all"], default="markdown")
    parser.add_argument("--min-severity", choices=["critical", "high", "medium", "low", "informational"],
                        default="medium")
    parser.add_argument("--output-dir", default=str(WORKSPACE))
    args = parser.parse_args()

    conn = initialize_database()
    run, findings = get_run_and_findings(conn, args.run_id, args.min_severity)

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    run_id = run["id"]

    print(f"Generating report for run {run_id}: {len(findings)} confirmed findings", file=sys.stderr)

    formats = ["markdown", "json", "sarif"] if args.format == "all" else [args.format]

    for fmt in formats:
        if fmt == "markdown":
            content = generate_markdown(run, findings)
            out_path = out_dir / f"report_{run_id}.md"
            out_path.write_text(content)
            print(f"Markdown report: {out_path}")
        elif fmt == "json":
            data = generate_json(run, findings)
            out_path = out_dir / f"report_{run_id}.json"
            out_path.write_text(json.dumps(data, indent=2))
            print(f"JSON report:     {out_path}")
        elif fmt == "sarif":
            data = generate_sarif(run, findings)
            out_path = out_dir / f"report_{run_id}.sarif"
            out_path.write_text(json.dumps(data, indent=2))
            print(f"SARIF report:    {out_path}")


if __name__ == "__main__":
    main()
