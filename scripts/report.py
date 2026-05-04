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

            # Show nearest route if available
            if f.get("notes"):
                try:
                    notes = json.loads(f["notes"]) if isinstance(f["notes"], str) else f["notes"]
                    if isinstance(notes, dict) and notes.get("nearest_route"):
                        r = notes["nearest_route"]
                        lines.append(f"  \n**Entry Point:** `{r.get('method', 'ANY')} {r.get('path', '?')}` ({Path(r.get('file_path', '')).name}:{r.get('line', '?')})")
                except (json.JSONDecodeError, TypeError, AttributeError):
                    pass

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
                lines.append("#### Data Flow\n")
                try:
                    path_steps = json.loads(f["taint_path"]) if isinstance(f["taint_path"], str) else f["taint_path"]
                    if isinstance(path_steps, list) and path_steps:
                        if isinstance(path_steps[0], dict):
                            # Rich format: [{step, file, line, code, role}, ...]
                            for j, step in enumerate(path_steps, 1):
                                role = step.get("role", "propagator")
                                role_label = {
                                    "source": "SOURCE (user input enters here)",
                                    "propagator": "PROPAGATES",
                                    "sink": "SINK (vulnerable call)",
                                    "sanitizer-bypass": "SANITIZER BYPASS",
                                }.get(role, role.upper())
                                file_info = f"`{step.get('file', '')}:{step.get('line', '?')}`"
                                code = step.get("code", step.get("code_snippet", ""))
                                lines.append(f"**Step {j} — {role_label}** at {file_info}")
                                if code:
                                    lang_hint = f.get("language") or ""
                                    lines.append(f"```{lang_hint}")
                                    lines.append(code.strip())
                                    lines.append("```")
                                lines.append("")
                        else:
                            # Simple list of strings
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


def generate_html(run, findings) -> str:
    """Generate a standalone HTML report with inline CSS, no external dependencies."""
    from collections import defaultdict

    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    sev_counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    # Severity badge colours
    sev_colors = {
        "critical": ("#ff4444", "#fff"),
        "high": ("#ff8c00", "#fff"),
        "medium": ("#ffd700", "#222"),
        "low": ("#4caf50", "#fff"),
        "informational": ("#2196f3", "#fff"),
    }

    def _badge(sev: str) -> str:
        bg, fg = sev_colors.get(sev, ("#888", "#fff"))
        return (f'<span style="background:{bg};color:{fg};padding:2px 8px;'
                f'border-radius:4px;font-size:0.8em;font-weight:bold;'
                f'text-transform:uppercase">{sev}</span>')

    def _esc(text: str) -> str:
        """HTML-escape a string."""
        if not text:
            return ""
        return (text
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;"))

    # Build ASCII bar chart for executive summary
    max_count = max(sev_counts.values()) if sev_counts.values() else 1
    bar_width = 30

    def _bar(count: int) -> str:
        if max_count == 0:
            return ""
        filled = round(count / max_count * bar_width)
        return "&#9608;" * filled + "&#9617;" * (bar_width - filled)

    # Group findings by severity
    by_sev = defaultdict(list)
    for f in findings:
        by_sev[f["severity"]].append(f)

    # Table of contents entries
    toc_items = []
    for sev in ["critical", "high", "medium", "low", "informational"]:
        if by_sev.get(sev):
            toc_items.append(
                f'<li><a href="#sev-{sev}">{sev.capitalize()} ({len(by_sev[sev])})</a></li>'
            )

    # Build findings HTML
    findings_html_parts = []
    for sev in ["critical", "high", "medium", "low", "informational"]:
        sev_list = by_sev.get(sev, [])
        if not sev_list:
            continue
        bg, fg = sev_colors.get(sev, ("#888", "#fff"))
        findings_html_parts.append(
            f'<section id="sev-{sev}">'
            f'<h2 style="border-left:6px solid {bg};padding-left:12px;margin-top:2em">'
            f'{sev.capitalize()} Findings ({len(sev_list)})</h2>'
        )
        for idx, f in enumerate(sev_list, 1):
            title_esc = _esc(f["title"])
            file_esc = _esc(f["file_path"])
            line = f["line_start"] or "?"

            # Taint path
            taint_path_html = ""
            if f.get("taint_path"):
                try:
                    steps = (json.loads(f["taint_path"])
                             if isinstance(f["taint_path"], str) else f["taint_path"])
                    if isinstance(steps, list):
                        items = "".join(f"<li><code>{_esc(str(s))}</code></li>" for s in steps)
                        taint_path_html = f"<p><strong>Taint Path:</strong></p><ol>{items}</ol>"
                    else:
                        taint_path_html = f"<p><strong>Taint Path:</strong> <code>{_esc(str(f['taint_path']))}</code></p>"
                except (json.JSONDecodeError, TypeError):
                    taint_path_html = f"<p><strong>Taint Path:</strong> <code>{_esc(str(f['taint_path']))}</code></p>"

            source_sink_html = ""
            if f.get("taint_source") or f.get("taint_sink"):
                if f.get("taint_source"):
                    source_sink_html += f"<p><strong>Source:</strong> <code>{_esc(f['taint_source'])}</code></p>"
                if f.get("taint_sink"):
                    source_sink_html += f"<p><strong>Sink:</strong> <code>{_esc(f['taint_sink'])}</code></p>"

            snippet_html = ""
            if f.get("code_snippet"):
                snippet_html = (
                    f'<details open><summary style="cursor:pointer;font-weight:bold">Evidence</summary>'
                    f'<pre style="background:#1e1e1e;color:#d4d4d4;padding:12px;border-radius:4px;'
                    f'overflow-x:auto;font-size:0.85em"><code>{_esc(f["code_snippet"])}</code></pre>'
                    f'</details>'
                )

            meta_parts = []
            if f.get("cwe"):
                meta_parts.append(f'<span><strong>CWE:</strong> {_esc(f["cwe"])}</span>')
            if f.get("owasp"):
                meta_parts.append(f'<span><strong>OWASP:</strong> {_esc(f["owasp"])}</span>')
            if f.get("cvss_score"):
                cvss_str = str(f["cvss_score"])
                if f.get("cvss_vector"):
                    cvss_str += f' <small>({_esc(f["cvss_vector"])})</small>'
                meta_parts.append(f'<span><strong>CVSS:</strong> {cvss_str}</span>')
            if f.get("confidence"):
                meta_parts.append(f'<span><strong>Confidence:</strong> {_esc(f["confidence"].capitalize())}</span>')

            meta_html = (
                '<div style="display:flex;gap:16px;flex-wrap:wrap;margin:8px 0;font-size:0.9em">'
                + "".join(meta_parts)
                + "</div>"
            ) if meta_parts else ""

            remediation_html = ""
            if f.get("remediation"):
                remediation_html = (
                    f'<details><summary style="cursor:pointer;font-weight:bold">Remediation</summary>'
                    f'<p style="margin-top:8px">{_esc(f["remediation"])}</p></details>'
                )

            findings_html_parts.append(
                f'<details open style="margin:16px 0;border:1px solid #ddd;border-radius:6px">'
                f'<summary style="padding:12px 16px;cursor:pointer;background:#f8f8f8;'
                f'border-radius:6px;list-style:none;display:flex;align-items:center;gap:10px">'
                f'{_badge(sev)}'
                f'<strong style="flex:1">{idx}. {title_esc}</strong>'
                f'<code style="font-size:0.8em;color:#666">{file_esc}:{line}</code>'
                f'</summary>'
                f'<div style="padding:16px">'
                f'<p><strong>File:</strong> <code>{file_esc}</code> line {line}</p>'
                f'{meta_html}'
                f'{"<p>" + _esc(f["description"]) + "</p>" if f.get("description") else ""}'
                f'{snippet_html}'
                f'{taint_path_html}'
                f'{source_sink_html}'
                f'{remediation_html}'
                f'</div>'
                f'</details>'
            )
        findings_html_parts.append("</section>")

    findings_html = "\n".join(findings_html_parts)
    toc_html = "\n".join(toc_items)

    # Bar chart rows
    bar_rows = []
    for sev in ["critical", "high", "medium", "low", "informational"]:
        count = sev_counts.get(sev, 0)
        if count == 0:
            continue
        bg, _ = sev_colors.get(sev, ("#888", "#fff"))
        bar_rows.append(
            f'<tr>'
            f'<td style="padding:4px 8px;text-align:right;font-weight:bold;text-transform:capitalize">{sev}</td>'
            f'<td style="padding:4px 8px;font-family:monospace;color:{bg}">{_bar(count)}</td>'
            f'<td style="padding:4px 8px;font-weight:bold">{count}</td>'
            f'</tr>'
        )
    bar_table = (
        '<table style="border-collapse:collapse;margin:12px 0">'
        + "".join(bar_rows)
        + f'<tr><td style="padding:4px 8px;text-align:right;font-weight:bold">Total</td>'
        f'<td></td><td style="padding:4px 8px;font-weight:bold">{len(findings)}</td></tr>'
        + "</table>"
    )

    top_issue_html = ""
    if findings:
        top = findings[0]
        top_issue_html = (
            f'<p>Most critical issue: <strong>{_esc(top["title"])}</strong> '
            f'in <code>{_esc(top["file_path"])}</code> '
            f'(CVSS: {top["cvss_score"] or "N/A"}). '
            f'Immediate remediation required for all Critical and High findings.</p>'
        )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Code-VulnScan Security Report — {_esc(run['path'])}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    line-height: 1.6;
    color: #222;
    background: #fff;
    margin: 0;
    padding: 0 16px 40px;
    max-width: 1100px;
    margin: 0 auto;
  }}
  @media (prefers-color-scheme: dark) {{
    body {{ background: #111; color: #ddd; }}
    summary {{ background: #1e1e1e !important; color: #ddd; }}
    details {{ border-color: #444 !important; }}
    code {{ background: #2a2a2a; }}
    a {{ color: #7eb8f7; }}
  }}
  h1 {{ border-bottom: 2px solid #333; padding-bottom: 8px; }}
  code {{
    background: #f0f0f0;
    padding: 1px 5px;
    border-radius: 3px;
    font-family: "SFMono-Regular", Consolas, monospace;
    font-size: 0.9em;
  }}
  a {{ color: #0066cc; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  details > summary::-webkit-details-marker {{ display: none; }}
  details > summary::before {{ content: "▶ "; font-size: 0.75em; }}
  details[open] > summary::before {{ content: "▼ "; font-size: 0.75em; }}
  nav {{ background: #f5f5f5; padding: 16px; border-radius: 6px; margin: 16px 0; }}
  nav ul {{ margin: 0; padding-left: 20px; }}
  .meta-bar {{ background: #f9f9f9; border: 1px solid #e0e0e0; border-radius: 6px;
               padding: 12px 16px; margin: 16px 0; font-size: 0.9em; }}
</style>
</head>
<body>
<h1>Security Vulnerability Report &mdash; Code-VulnScan</h1>
<div class="meta-bar">
  <strong>Target:</strong> <code>{_esc(run['path'])}</code>&nbsp;&nbsp;
  <strong>Scan ID:</strong> <code>{_esc(str(run['id']))}</code>&nbsp;&nbsp;
  <strong>Generated:</strong> {ts}&nbsp;&nbsp;
  <strong>Tool:</strong> Code-VulnScan v1.0.0
</div>

<nav>
  <strong>Table of Contents</strong>
  <ul>
    <li><a href="#summary">Executive Summary</a></li>
    {toc_html}
    <li><a href="#checklist">Remediation Checklist</a></li>
  </ul>
</nav>

<section id="summary">
  <h2>Executive Summary</h2>
  {bar_table}
  {top_issue_html}
</section>

{findings_html}

<section id="checklist">
  <h2>Remediation Priority Checklist</h2>
  {"".join(
      f'<h3>{sev.capitalize()} &mdash; Fix Immediately</h3><ul>'
      + "".join(
          f'<li>{_badge(sev)} {_esc(f["title"])} &mdash; '
          f'<code>{_esc(f["file_path"])}:{f["line_start"] or "?"}</code></li>'
          for f in by_sev[sev]
      )
      + "</ul>"
      for sev in ["critical", "high", "medium"]
      if by_sev.get(sev)
  )}
</section>

<hr>
<footer style="font-size:0.8em;color:#888;margin-top:24px">
  Report generated by
  <a href="https://github.com/Bhanunamikaze/Code-VulnScan-Skill">Code-VulnScan</a>
  &mdash; Scan ID: {_esc(str(run['id']))} &mdash; {ts}
</footer>
</body>
</html>"""
    return html


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
    parser.add_argument("--format", choices=["markdown", "json", "sarif", "html", "all"], default="markdown")
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

    formats = ["markdown", "json", "sarif", "html"] if args.format == "all" else [args.format]

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
        elif fmt == "html":
            content = generate_html(run, findings)
            out_path = out_dir / f"report_{run_id}.html"
            out_path.write_text(content)
            print(f"HTML report:     {out_path}")


if __name__ == "__main__":
    main()
