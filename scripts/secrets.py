#!/usr/bin/env python3
"""
Secret detector — finds hardcoded credentials, API keys, and high-entropy strings.

Usage:
  python3 scripts/secrets.py --path <dir> [--min-entropy 4.5] [--include-tests]
"""

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from scripts.utils.files import enumerate_files, read_file_lines
from scripts.utils.entropy import scan_line_for_secrets, SECRET_PATTERNS, HIGH_ENTROPY_THRESHOLD

SKIP_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
                   ".ttf", ".eot", ".mp4", ".mp3", ".pdf", ".zip", ".gz", ".tar",
                   ".lock", ".pyc", ".class", ".jar", ".war", ".dll", ".exe", ".so",
                   ".min.js", ".min.css"}

ALWAYS_SCAN = {".env", ".env.local", ".env.production", ".env.staging",
               ".env.example", ".envrc", "credentials", ".netrc"}


def should_scan_file(file_path: Path) -> bool:
    name = file_path.name.lower()
    if name in ALWAYS_SCAN or any(name.endswith(ext) for ext in ALWAYS_SCAN):
        return True
    for ext in SKIP_EXTENSIONS:
        if name.endswith(ext):
            return False
    return True


def scan_path(base_path: Path, min_entropy: float = HIGH_ENTROPY_THRESHOLD,
              include_tests: bool = False) -> list:
    all_findings = []
    base_path = Path(base_path).resolve()

    files = enumerate_files(base_path, include_tests=include_tests, include_config=True)

    # Also scan config/env files that enumerate_files might skip
    for special in ALWAYS_SCAN:
        p = base_path / special
        if p.exists() and p.is_file():
            # Check it's not already in files list
            if not any(f["path"] == p for f in files):
                files.append({"path": p, "relative": special, "language": "dotenv",
                              "size": p.stat().st_size, "is_test": False})

    for file_info in files:
        file_path = file_info["path"]
        if not should_scan_file(file_path):
            continue

        lines = read_file_lines(file_path)
        for i, line in enumerate(lines, start=1):
            hits = scan_line_for_secrets(line, i, str(file_path.relative_to(base_path)))
            # Filter by entropy threshold
            hits = [h for h in hits if h.get("entropy", 0) >= min_entropy or h.get("detection_method") == "pattern"]
            all_findings.extend(hits)

    return all_findings


def scan_git_history(repo_path: str, max_commits: int = 200) -> list:
    """Scan git history for secrets in committed diffs.

    Checks up to *max_commits* commits and scans every added line (+) in each
    diff for secret patterns.  Returns findings with commit metadata.
    """
    repo = Path(repo_path).resolve()

    # Verify git is available
    if not shutil.which("git"):
        print("Warning: git not found in PATH — skipping git history scan", file=sys.stderr)
        return []

    # Verify this is actually a git repository
    check = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--is-inside-work-tree"],
        capture_output=True, text=True,
    )
    if check.returncode != 0:
        print(f"Warning: {repo} is not a git repository — skipping git history scan",
              file=sys.stderr)
        return []

    # Get commit list: hash + subject on one line
    log_result = subprocess.run(
        ["git", "-C", str(repo), "log", "--oneline", f"-n{max_commits}"],
        capture_output=True, text=True,
    )
    if log_result.returncode != 0:
        print(f"Warning: git log failed: {log_result.stderr.strip()}", file=sys.stderr)
        return []

    commit_lines = [l.strip() for l in log_result.stdout.splitlines() if l.strip()]
    if not commit_lines:
        return []

    print(f"Scanning git history: {len(commit_lines)} commits in {repo}", file=sys.stderr)

    all_findings = []
    seen_keys: set = set()

    for entry in commit_lines:
        parts = entry.split(" ", 1)
        commit_hash = parts[0]
        commit_msg = parts[1] if len(parts) > 1 else ""

        diff_result = subprocess.run(
            ["git", "-C", str(repo), "diff", f"{commit_hash}^..{commit_hash}"],
            capture_output=True, text=True,
        )
        if diff_result.returncode != 0:
            # First commit has no parent — use show instead
            diff_result = subprocess.run(
                ["git", "-C", str(repo), "show", commit_hash],
                capture_output=True, text=True,
            )
            if diff_result.returncode != 0:
                continue

        current_file = f"<git:{commit_hash[:8]}>"
        diff_line_num = 0

        for diff_line in diff_result.stdout.splitlines():
            # Track which file we're in
            if diff_line.startswith("+++ b/"):
                current_file = diff_line[6:]
                diff_line_num = 0
                continue
            if diff_line.startswith("@@"):
                # Parse hunk header to get starting line number
                m = re.search(r"\+(\d+)", diff_line)
                diff_line_num = int(m.group(1)) if m else 0
                continue
            if diff_line.startswith("+") and not diff_line.startswith("+++"):
                diff_line_num += 1
                added_content = diff_line[1:]  # strip the leading +
                hits = scan_line_for_secrets(added_content, diff_line_num, current_file)
                for hit in hits:
                    dedup_key = (commit_hash, current_file, diff_line_num, hit["secret_type"])
                    if dedup_key in seen_keys:
                        continue
                    seen_keys.add(dedup_key)
                    hit["git_commit"] = commit_hash
                    hit["git_commit_message"] = commit_msg
                    hit["detection_context"] = "git_history"
                    all_findings.append(hit)

    print(f"Git history scan complete: {len(all_findings)} findings", file=sys.stderr)
    return all_findings


def deduplicate(findings: list) -> list:
    seen = set()
    out = []
    for f in findings:
        key = (f["file_path"], f["line_start"], f["secret_type"])
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def main():
    parser = argparse.ArgumentParser(description="Code-VulnScan secret detector")
    parser.add_argument("--path", required=True, help="Path to scan")
    parser.add_argument("--min-entropy", type=float, default=HIGH_ENTROPY_THRESHOLD,
                        help=f"Minimum entropy threshold (default: {HIGH_ENTROPY_THRESHOLD})")
    parser.add_argument("--include-tests", action="store_true")
    parser.add_argument("--git-history", action="store_true",
                        help="Also scan git commit history for secrets (up to --max-commits commits)")
    parser.add_argument("--max-commits", type=int, default=200,
                        help="Maximum number of git commits to scan (default: 200)")
    parser.add_argument("--output", help="Output JSON file path")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    base = Path(args.path)
    if not base.exists():
        print(f"Error: path not found: {base}", file=sys.stderr)
        sys.exit(1)

    print(f"Scanning for secrets in: {base}", file=sys.stderr)
    findings = scan_path(base, args.min_entropy, args.include_tests)

    if args.git_history:
        git_findings = scan_git_history(str(base), max_commits=args.max_commits)
        findings.extend(git_findings)

    findings = deduplicate(findings)

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: (severity_order.get(f.get("severity", "medium"), 2), f["file_path"], f["line_start"]))

    # Remove raw_match from output (never log actual secrets)
    output_findings = []
    for f in findings:
        clean = {k: v for k, v in f.items() if k != "raw_match"}
        output_findings.append(clean)

    summary = {
        "total": len(output_findings),
        "critical": sum(1 for f in output_findings if f.get("severity") == "critical"),
        "high": sum(1 for f in output_findings if f.get("severity") == "high"),
        "medium": sum(1 for f in output_findings if f.get("severity") == "medium"),
        "by_type": {},
    }
    for f in output_findings:
        t = f.get("secret_type", "unknown")
        summary["by_type"][t] = summary["by_type"].get(t, 0) + 1

    result = {"summary": summary, "findings": output_findings}
    indent = 2 if args.pretty else None
    output_str = json.dumps(result, indent=indent)

    if args.output:
        Path(args.output).write_text(output_str)
        print(f"Results written to: {args.output}", file=sys.stderr)
    else:
        print(output_str)

    print(f"\nSecrets scan complete: {summary['total']} findings "
          f"({summary['critical']} critical, {summary['high']} high, {summary['medium']} medium)",
          file=sys.stderr)

    if output_findings:
        print("\nTop findings (agent must verify each before reporting):", file=sys.stderr)
        for f in output_findings[:10]:
            print(f"  [{f.get('severity','?').upper():8}] {f['file_path']}:{f['line_start']} "
                  f"— {f['secret_type']} — {f['evidence']}", file=sys.stderr)


if __name__ == "__main__":
    main()
