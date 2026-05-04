"""JS/TS taint analysis — tree-sitter when available, variable-tracking fallback."""
try:
    import tree_sitter  # type: ignore
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False

from scripts.taint import analyze_with_variable_tracking


def analyze_js(content: str, file_path: str, language: str = "javascript") -> dict:
    if TREE_SITTER_AVAILABLE:
        # TODO: implement tree-sitter based analysis
        pass
    return analyze_with_variable_tracking(content, file_path, language)
