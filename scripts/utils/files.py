"""File enumeration utilities for Code-VulnScan."""

from pathlib import Path
from .languages import (
    detect_language, should_skip_dir, is_test_file, is_generated_file,
    SOURCE_EXTENSIONS, CONFIG_EXTENSIONS, EXTENSION_MAP,
)

MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024  # 2MB — skip very large generated files


def enumerate_files(
    base_path: Path,
    include_langs: list = None,
    exclude_dirs: list = None,
    include_tests: bool = False,
    include_config: bool = True,
) -> list:
    """Walk a directory and return a list of dicts describing each scannable file."""
    base_path = Path(base_path).resolve()
    extra_skip = set(d.lower() for d in (exclude_dirs or []))
    results = []

    for p in base_path.rglob("*"):
        if not p.is_file():
            continue

        # Skip dirs
        if any(should_skip_dir(parent) or parent.name.lower() in extra_skip
               for parent in p.parents):
            continue

        # Skip large files
        try:
            if p.stat().st_size > MAX_FILE_SIZE_BYTES:
                continue
        except OSError:
            continue

        lang = detect_language(p)

        # Filter by language
        if include_langs and lang not in include_langs:
            ext = p.suffix.lower()
            # Allow config files regardless
            if not (include_config and ext in CONFIG_EXTENSIONS):
                continue

        if lang == "unknown":
            continue

        # Skip generated/minified
        if is_generated_file(p):
            continue

        # Tests
        if not include_tests and is_test_file(p):
            continue

        rel = p.relative_to(base_path)
        results.append({
            "path": p,
            "relative": str(rel),
            "language": lang,
            "size": p.stat().st_size,
            "is_test": is_test_file(p),
        })

    return sorted(results, key=lambda f: f["relative"])


def read_file_lines(file_path: Path) -> list:
    """Read file, returning list of lines. Returns empty list on decode error."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            return f.readlines()
    except (OSError, PermissionError):
        return []


def read_file(file_path: Path) -> str:
    """Read file content as string."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except (OSError, PermissionError):
        return ""


def get_snippet(lines: list, line_num: int, context: int = 3) -> str:
    """Extract a code snippet around a line number with context."""
    start = max(0, line_num - 1 - context)
    end = min(len(lines), line_num + context)
    snippet_lines = []
    for i, line in enumerate(lines[start:end], start=start + 1):
        marker = ">>>" if i == line_num else "   "
        snippet_lines.append(f"{marker} {i:4d}: {line.rstrip()}")
    return "\n".join(snippet_lines)


def group_files_by_language(files: list) -> dict:
    """Group file list by language."""
    groups = {}
    for f in files:
        lang = f["language"]
        groups.setdefault(lang, []).append(f)
    return groups


def count_by_language(files: list) -> dict:
    counts = {}
    for f in files:
        lang = f["language"]
        counts[lang] = counts.get(lang, 0) + 1
    return dict(sorted(counts.items(), key=lambda x: -x[1]))
