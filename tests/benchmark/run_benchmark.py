#!/usr/bin/env python3
"""
Benchmark harness for Code-VulnScan.

Measures precision, recall, and F1 per vulnerability class by running the
scanner against labeled fixture files in tests/benchmark/vulnerable/ and
tests/benchmark/safe/, then comparing the findings against labels.json.

Usage:
    python tests/benchmark/run_benchmark.py
    python tests/benchmark/run_benchmark.py --save-baseline
    python tests/benchmark/run_benchmark.py --results-dir /custom/results/dir
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

# Ensure project root is on sys.path so scripts.* imports work
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

try:
    from scripts.utils.patterns import scan_file_for_candidates
    from scripts.taint import analyze_file
    from scripts.utils.languages import detect_language
except ImportError as exc:
    print(f"[ERROR] Could not import scanner modules: {exc}", file=sys.stderr)
    print("       Make sure you run this script from the project root:", file=sys.stderr)
    print("           python tests/benchmark/run_benchmark.py", file=sys.stderr)
    sys.exit(1)

BENCHMARK_DIR = Path(__file__).parent
LABELS_FILE = BENCHMARK_DIR / "labels.json"
RESULTS_DIR = BENCHMARK_DIR / "results"
BASELINE_FILE = BENCHMARK_DIR / "baseline.json"

# Mapping from vuln_type strings used in patterns/taint to our label type keys
VULN_TYPE_ALIASES: dict[str, str] = {
    "sqli": "sqli",
    "sql_injection": "sqli",
    "sql injection": "sqli",
    "cmdi": "cmdi",
    "command_injection": "cmdi",
    "command injection": "cmdi",
    "rce": "cmdi",
    "path_traversal": "path_traversal",
    "path traversal": "path_traversal",
    "lfi": "path_traversal",
    "directory_traversal": "path_traversal",
    "xss": "xss",
    "cross_site_scripting": "xss",
    "cross-site scripting": "xss",
    "ssti": "ssti",
    "server_side_template_injection": "ssti",
    "ssrf": "ssrf",
    "server_side_request_forgery": "ssrf",
    "deserialization": "deserialization",
    "insecure_deserialization": "deserialization",
    "xxe": "xxe",
    "xml_external_entity": "xxe",
    "open_redirect": "open_redirect",
    "open redirect": "open_redirect",
    "proto_pollution": "proto_pollution",
    "prototype_pollution": "proto_pollution",
}


def normalize_vuln_type(raw: str) -> str:
    """Normalize a raw vuln_type string to a canonical label type."""
    return VULN_TYPE_ALIASES.get(raw.lower().strip(), raw.lower().strip())


def read_file_safe(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def scan_file(file_path: Path) -> list[dict]:
    """Run both pattern scan and taint analysis on a file, returning merged findings."""
    language = detect_language(file_path)
    content = read_file_safe(file_path)
    if not content:
        return []

    findings: list[dict] = []

    # Pattern-based scan
    try:
        candidates = scan_file_for_candidates(file_path, content, language)
        for c in candidates:
            findings.append({
                "source": "pattern",
                "vuln_type": normalize_vuln_type(c.get("vuln_type", "")),
                "line": c.get("line_start", 0),
                "confidence": c.get("confidence", "possible"),
                "detail": c.get("title", ""),
            })
    except Exception as exc:
        print(f"  [WARN] pattern scan failed for {file_path.name}: {exc}", file=sys.stderr)

    # Taint analysis
    try:
        taint_result = analyze_file(str(file_path), language)
        for path_info in taint_result.get("potential_paths", []):
            findings.append({
                "source": "taint",
                "vuln_type": normalize_vuln_type(path_info.get("sink_type", "")),
                "line": path_info.get("sink_line", 0),
                "confidence": path_info.get("confidence", "possible"),
                "detail": path_info.get("sink_name", ""),
            })
    except Exception as exc:
        print(f"  [WARN] taint analysis failed for {file_path.name}: {exc}", file=sys.stderr)

    return findings


def collect_fixture_files(directory: Path) -> list[Path]:
    """Recursively collect all source files in a benchmark sub-directory."""
    result = []
    for p in sorted(directory.rglob("*")):
        if p.is_file() and p.suffix in (
            ".py", ".js", ".ts", ".java", ".go", ".php",
            ".rb", ".c", ".cpp", ".cs", ".rs",
        ):
            result.append(p)
    return result


def relative_label_key(file_path: Path) -> str:
    """Convert an absolute file path to the key format used in labels.json.

    e.g. .../tests/benchmark/vulnerable/python/sqli_001.py
         -> vulnerable/python/sqli_001.py
    """
    try:
        return str(file_path.relative_to(BENCHMARK_DIR))
    except ValueError:
        return str(file_path)


# ---------------------------------------------------------------------------
# Metrics helpers
# ---------------------------------------------------------------------------

def compute_metrics(tp: int, fp: int, fn: int) -> dict:
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) > 0 else 0.0)
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def print_table(per_class: dict, overall: dict) -> None:
    header = f"{'Class':<22} {'TP':>4} {'FP':>4} {'FN':>4} {'Precision':>10} {'Recall':>8} {'F1':>8}"
    print()
    print("=" * len(header))
    print("  Code-VulnScan Benchmark Results")
    print("=" * len(header))
    print(header)
    print("-" * len(header))
    for cls in sorted(per_class):
        m = per_class[cls]
        print(
            f"  {cls:<20} {m['tp']:>4} {m['fp']:>4} {m['fn']:>4}"
            f" {m['precision']:>10.4f} {m['recall']:>8.4f} {m['f1']:>8.4f}"
        )
    print("-" * len(header))
    m = overall
    print(
        f"  {'OVERALL':<20} {m['tp']:>4} {m['fp']:>4} {m['fn']:>4}"
        f" {m['precision']:>10.4f} {m['recall']:>8.4f} {m['f1']:>8.4f}"
    )
    print("=" * len(header))
    print()


# ---------------------------------------------------------------------------
# Main benchmark logic
# ---------------------------------------------------------------------------

def run_benchmark() -> dict:
    if not LABELS_FILE.exists():
        print(f"[ERROR] labels.json not found at {LABELS_FILE}", file=sys.stderr)
        sys.exit(1)

    with open(LABELS_FILE) as f:
        labels: dict = json.load(f)

    vuln_dir = BENCHMARK_DIR / "vulnerable"
    safe_dir = BENCHMARK_DIR / "safe"

    # Keyed by vuln_type: {"tp": int, "fp": int, "fn": int}
    per_class: dict[str, dict] = {}

    def ensure_class(cls: str):
        if cls not in per_class:
            per_class[cls] = {"tp": 0, "fp": 0, "fn": 0}

    file_results: list[dict] = []

    # ── Vulnerable files ────────────────────────────────────────────────────
    print("\nScanning vulnerable fixtures...")
    for file_path in collect_fixture_files(vuln_dir):
        rel_key = relative_label_key(file_path)
        expected_labels = labels.get(rel_key, [])
        expected_types = {lbl["type"] for lbl in expected_labels}

        print(f"  {rel_key}", end=" ... ", flush=True)
        findings = scan_file(file_path)
        found_types = {normalize_vuln_type(f["vuln_type"]) for f in findings if f["vuln_type"]}

        file_record = {
            "file": rel_key,
            "kind": "vulnerable",
            "expected": list(expected_types),
            "found": list(found_types),
            "findings_count": len(findings),
            "tp": [],
            "fn": [],
            "fp_here": [],
        }

        # True positives and false negatives from the expected set
        for exp_type in expected_types:
            ensure_class(exp_type)
            if exp_type in found_types:
                per_class[exp_type]["tp"] += 1
                file_record["tp"].append(exp_type)
            else:
                per_class[exp_type]["fn"] += 1
                file_record["fn"].append(exp_type)

        # False positives: scanner found something not in expected set
        # (for vulnerable files we only penalise wrong vuln_type if the file
        #  is fully labeled — i.e. labels exist for it)
        if expected_labels:
            for found_type in found_types:
                if found_type and found_type not in expected_types:
                    ensure_class(found_type)
                    per_class[found_type]["fp"] += 1
                    file_record["fp_here"].append(found_type)

        status = "OK" if file_record["fn"] == [] else f"MISS:{file_record['fn']}"
        print(status)
        file_results.append(file_record)

    # ── Safe files ──────────────────────────────────────────────────────────
    print("\nScanning safe fixtures...")
    for file_path in collect_fixture_files(safe_dir):
        rel_key = relative_label_key(file_path)

        print(f"  {rel_key}", end=" ... ", flush=True)
        findings = scan_file(file_path)
        found_types = {normalize_vuln_type(f["vuln_type"]) for f in findings if f["vuln_type"]}

        file_record = {
            "file": rel_key,
            "kind": "safe",
            "expected": [],
            "found": list(found_types),
            "findings_count": len(findings),
            "tp": [],
            "fn": [],
            "fp_here": [],
        }

        # Every finding in a safe file is a false positive
        for found_type in found_types:
            if found_type:
                ensure_class(found_type)
                per_class[found_type]["fp"] += 1
                file_record["fp_here"].append(found_type)

        status = "CLEAN" if not found_types else f"FP:{list(found_types)}"
        print(status)
        file_results.append(file_record)

    # ── Aggregate metrics ───────────────────────────────────────────────────
    total_tp = sum(v["tp"] for v in per_class.values())
    total_fp = sum(v["fp"] for v in per_class.values())
    total_fn = sum(v["fn"] for v in per_class.values())
    overall = compute_metrics(total_tp, total_fp, total_fn)

    per_class_metrics = {cls: compute_metrics(**counts) for cls, counts in per_class.items()}

    print_table(per_class_metrics, overall)

    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "overall": overall,
        "per_class": per_class_metrics,
        "file_results": file_results,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Run the Code-VulnScan benchmark and measure precision/recall."
    )
    parser.add_argument(
        "--save-baseline",
        action="store_true",
        help="Write results to tests/benchmark/baseline.json in addition to timestamped results.",
    )
    parser.add_argument(
        "--results-dir",
        default=str(RESULTS_DIR),
        help="Directory to write timestamped JSON result files (default: tests/benchmark/results/).",
    )
    args = parser.parse_args()

    results_dir = Path(args.results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)

    results = run_benchmark()

    # Save timestamped results
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    out_path = results_dir / f"{ts}.json"
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Results saved to: {out_path}")

    if args.save_baseline:
        with open(BASELINE_FILE, "w") as f:
            json.dump(results, f, indent=2)
        print(f"Baseline saved to: {BASELINE_FILE}")


if __name__ == "__main__":
    main()
