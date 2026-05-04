#!/usr/bin/env python3
"""
Code-VulnScan — main scan orchestrator.

Usage:
  python3 scripts/scan.py --path <dir> [--lang python,javascript] [--exclude vendor,tests]
  python3 scripts/scan.py --status-only
  python3 scripts/scan.py --update-findings workspace/confirmed_findings.json
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from scripts.utils.db import initialize_database, create_run, insert_finding, list_runs, get_findings, get_latest_run, update_finding_status
from scripts.utils.files import enumerate_files, read_file, get_snippet, count_by_language
from scripts.utils.languages import detect_language, detect_frameworks
from scripts.utils.patterns import scan_file_for_candidates


def cmd_status(conn):
    runs = list_runs(conn, limit=5)
    if not runs:
        print("No scan runs found.")
        return
    print(f"\n{'='*60}")
    print("Recent scan runs:")
    print(f"{'='*60}")
    for run in runs:
        findings = get_findings(conn, run_id=run["id"])
        confirmed = [f for f in findings if f["status"] in ("confirmed", "likely")]
        candidates = [f for f in findings if f["status"] == "candidate"]
        print(f"\nRun ID:    {run['id']}")
        print(f"Path:      {run['path']}")
        print(f"Timestamp: {run['timestamp']}")
        print(f"Status:    {run['status']}")
        print(f"Languages: {run['languages'] or 'auto-detected'}")
        print(f"Files:     {run['total_files']}")
        print(f"Candidates:{len(candidates)}  Confirmed: {len(confirmed)}")
    print()


def cmd_scan(conn, args):
    target = Path(args.path).resolve()
    if not target.exists():
        print(f"Error: path not found: {target}", file=sys.stderr)
        sys.exit(1)

    include_langs = [l.strip() for l in args.lang.split(",")] if args.lang else None
    exclude_dirs = [d.strip() for d in args.exclude.split(",")] if args.exclude else None

    print(f"\nCode-VulnScan — Enumerating: {target}")

    files = enumerate_files(
        target,
        include_langs=include_langs,
        exclude_dirs=exclude_dirs,
        include_tests=False,
        include_config=True,
    )

    lang_counts = count_by_language(files)
    print(f"Files found: {len(files)}")
    print("Languages:  " + ", ".join(f"{k}({v})" for k, v in lang_counts.items()))

    # Detect frameworks from high-priority files
    frameworks_seen = {}
    for f in files[:50]:
        content = read_file(f["path"])
        fws = detect_frameworks(f["path"], content, f["language"])
        for fw in fws:
            frameworks_seen[fw] = frameworks_seen.get(fw, 0) + 1

    if frameworks_seen:
        print("Frameworks: " + ", ".join(frameworks_seen.keys()))

    # Create run
    run_id = create_run(conn, str(target), list(lang_counts.keys()))
    conn.execute("UPDATE scan_runs SET total_files = ? WHERE id = ?", (len(files), run_id))
    conn.commit()

    print(f"\nRun ID: {run_id}")
    print("Running pattern-match sweep...")

    total_candidates = 0
    candidates_by_type = {}

    for file_info in files:
        lang = file_info["language"]
        content = read_file(file_info["path"])
        if not content:
            continue

        candidates = scan_file_for_candidates(file_info["path"], content, lang)
        lines = content.splitlines()

        for c in candidates:
            # Attach snippet
            line = c.get("line_start", 1)
            c["code_snippet"] = get_snippet(lines, line)
            insert_finding(conn, run_id, c)
            total_candidates += 1
            vtype = c.get("vuln_type", "unknown")
            candidates_by_type[vtype] = candidates_by_type.get(vtype, 0) + 1

    conn.execute("UPDATE scan_runs SET candidate_count = ?, status = 'pending_review' WHERE id = ?",
                 (total_candidates, run_id))
    conn.commit()

    print(f"\nPattern sweep complete.")
    print(f"Total candidates: {total_candidates}")

    if candidates_by_type:
        print("\nCandidates by type:")
        for vtype, count in sorted(candidates_by_type.items(), key=lambda x: -x[1]):
            print(f"  {vtype:<30} {count:>4}")

    print(f"\n{'='*60}")
    print("NEXT STEPS — Agent analysis required:")
    print("="*60)
    print("1. Read sub-skills/scan-strategy.md — build the scan plan")
    print("2. Read sub-skills/taint-analyzer.md — verify candidate taint paths")
    print("3. Read sub-skills/input-validator.md — check validation at entry points")
    print("4. Read sub-skills/business-logic-analyzer.md — logic and race conditions")
    print("5. Read sub-skills/api-security-reviewer.md — IDOR, mass assignment, rate limiting")
    print("6. Read sub-skills/auth-reviewer.md — authentication and authorization")
    print("7. Read sub-skills/crypto-reviewer.md — cryptography weaknesses")
    print("8. Run: python3 scripts/secrets.py --path", target)
    print("9. Run: python3 scripts/dependency.py --path", target)
    print("10. Read sub-skills/false-positive-filter.md — eliminate false positives")
    print("11. Read sub-skills/vuln-classifier.md — assign CWE/CVSS/severity")
    print(f"12. Run: python3 scripts/scan.py --update-findings workspace/confirmed_findings.json")
    print("13. Run: python3 scripts/report.py --format markdown")
    print(f"\nScan state: workspace/scan_state.db (run_id: {run_id})")


def cmd_update_findings(conn, findings_path: str):
    p = Path(findings_path)
    if not p.exists():
        print(f"Error: file not found: {p}", file=sys.stderr)
        sys.exit(1)

    with open(p) as f:
        findings = json.load(f)

    if not isinstance(findings, list):
        findings = [findings]

    run = get_latest_run(conn)
    if not run:
        print("Error: no scan run found. Run a scan first.", file=sys.stderr)
        sys.exit(1)

    run_id = run["id"]
    inserted = 0
    updated = 0

    for finding in findings:
        finding["run_id"] = run_id
        status = finding.get("status", "confirmed")
        existing = conn.execute(
            "SELECT id FROM findings WHERE file_path = ? AND line_start = ? AND vuln_type = ? AND run_id = ?",
            (finding.get("file_path"), finding.get("line_start"), finding.get("vuln_type"), run_id)
        ).fetchone()

        if existing:
            update_finding_status(
                conn, existing["id"], status,
                severity=finding.get("severity", "medium"),
                confidence=finding.get("confidence", "confirmed"),
                cwe=finding.get("cwe"),
                owasp=finding.get("owasp"),
                cvss_score=finding.get("cvss_score"),
                cvss_vector=finding.get("cvss_vector"),
                taint_path=json.dumps(finding.get("taint_path", [])),
                remediation=finding.get("remediation"),
                description=finding.get("description"),
                false_positive_analysis=finding.get("false_positive_analysis"),
            )
            updated += 1
        else:
            insert_finding(conn, run_id, finding)
            inserted += 1

    # Update confirmed count
    confirmed = get_findings(conn, run_id=run_id, status=["confirmed", "likely"])
    conn.execute("UPDATE scan_runs SET confirmed_count = ?, status = 'complete' WHERE id = ?",
                 (len(confirmed), run_id))
    conn.commit()

    print(f"Updated {updated} existing findings, inserted {inserted} new findings.")
    print(f"Total confirmed: {len(confirmed)}")


def main():
    parser = argparse.ArgumentParser(description="Code-VulnScan — codebase vulnerability scanner")
    parser.add_argument("--path", help="Path to codebase to scan")
    parser.add_argument("--lang", help="Comma-separated languages (e.g. python,javascript)")
    parser.add_argument("--exclude", help="Comma-separated directories to exclude")
    parser.add_argument("--status-only", action="store_true", help="Show scan status and exit")
    parser.add_argument("--update-findings", metavar="JSON_FILE", help="Update findings from a JSON file")
    parser.add_argument("--force", action="store_true", help="Force new run even if recent run exists")

    args = parser.parse_args()
    conn = initialize_database()

    if args.status_only:
        cmd_status(conn)
    elif args.update_findings:
        cmd_update_findings(conn, args.update_findings)
    elif args.path:
        cmd_scan(conn, args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
