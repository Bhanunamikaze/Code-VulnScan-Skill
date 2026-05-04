#!/usr/bin/env bash

set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/Bhanunamikaze/Code-VulnScan-Skill.git}"
SKILL_NAME="code-vulnscan"
TARGET="claude"
PROJECT_DIR="$(pwd)"
FORCE=0
INSTALL_DEPS=0
SOURCE_MODE="auto"
REPO_PATH=""
TEMP_DIR=""

REQUIRED_PATHS=(
    "SKILL.md"
    "scripts"
    "sub-skills"
    "resources"
)

usage() {
    cat <<'EOF'
Code-VulnScan Skill Installer

Installs the Code-VulnScan vulnerability scanning skill for AI coding assistants.

Usage:
  bash install.sh [options]

Options:
  --target <target>
      Install target. Supported targets:
        claude       → ~/.claude/skills/code-vulnscan          (Claude Code CLI / Desktop)
        codex        → ~/.codex/skills/code-vulnscan            (OpenAI Codex)
        antigravity  → <project>/.agent/skills/code-vulnscan   (Antigravity IDE)
        cursor       → <project>/.cursor/skills/code-vulnscan  (Cursor AI)
        windsurf     → <project>/.windsurf/skills/code-vulnscan (Windsurf IDE)
        continue     → <project>/.continue/skills/code-vulnscan (Continue.dev)
        global       → claude + codex (user-wide)
        project      → antigravity + cursor + windsurf + continue (project-local, all IDEs)
        all          → all targets
      Default: claude

  --project-dir <path>
      Project directory for project-local installs. Default: current directory

  --skill-name <name>
      Installed skill folder name. Default: code-vulnscan

  --repo-url <url>
      Git URL for remote source installs

  --source <auto|local|remote>
      Source mode. Default: auto (uses local checkout if SKILL.md present, else clones)

  --repo-path <path>
      Use a specific local checkout as the install source

  --install-deps
      Install optional Python dependencies (pip install -r requirements.txt)

  --force
      Overwrite an existing installed skill

  -h, --help
      Show this help

Examples:
  # Install for Claude Code (most common)
  bash install.sh --target claude

  # Install for all IDEs globally
  bash install.sh --target global

  # Install project-local for all supported project IDEs
  bash install.sh --target project --project-dir /path/to/your/project

  # Install for a specific IDE, project-local
  bash install.sh --target cursor --project-dir /path/to/your/project
  bash install.sh --target windsurf --project-dir /path/to/your/project
  bash install.sh --target antigravity --project-dir /path/to/your/project
  bash install.sh --target continue --project-dir /path/to/your/project

  # Install for Codex
  bash install.sh --target codex

  # Install all targets (project + global)
  bash install.sh --target all --project-dir /path/to/your/project

  # Install from a specific local checkout
  bash install.sh --target claude --repo-path /path/to/Code-VulnScan-Skill

  # Install with Python dependencies for local scripts
  bash install.sh --target claude --install-deps

Safer remote install (with SHA-256 checksum verification):
  curl -fsSLO https://raw.githubusercontent.com/Bhanunamikaze/Code-VulnScan-Skill/main/install.sh
  curl -fsSLO https://raw.githubusercontent.com/Bhanunamikaze/Code-VulnScan-Skill/main/install.sh.sha256
  sha256sum -c install.sh.sha256
  bash install.sh --target claude

After install, restart your IDE/agent session to pick up the new skill.
EOF
}

cleanup() {
    if [[ -n "${TEMP_DIR}" && -d "${TEMP_DIR}" ]]; then
        rm -rf "${TEMP_DIR}"
    fi
}

trap cleanup EXIT

require_cmd() {
    local cmd="$1"
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        echo "Error: required command not found: ${cmd}" >&2
        exit 1
    fi
}

resolve_dir() {
    local dir="$1"
    if [[ ! -d "${dir}" ]]; then
        echo "Error: directory not found: ${dir}" >&2
        exit 1
    fi
    (cd "${dir}" && pwd)
}

copy_skill() {
    local src="$1"
    local dest="$2"
    local label="$3"

    if [[ -e "${dest}" && "${FORCE}" -ne 1 ]]; then
        echo "Error: ${label} target already exists: ${dest}" >&2
        echo "Use --force to overwrite." >&2
        exit 1
    fi

    for required_path in "${REQUIRED_PATHS[@]}"; do
        if [[ ! -e "${src}/${required_path}" ]]; then
            echo "Error: required skill path not found: ${src}/${required_path}" >&2
            exit 1
        fi
    done

    mkdir -p "$(dirname "${dest}")"
    if [[ -e "${dest}" ]]; then
        rm -rf "${dest}"
    fi
    mkdir -p "${dest}"

    if command -v rsync >/dev/null 2>&1; then
        for required_path in "${REQUIRED_PATHS[@]}"; do
            rsync -a \
                --exclude "__pycache__/" \
                --exclude "*.pyc" \
                --exclude "*.pyc" \
                "${src}/${required_path}" "${dest}/"
        done
    else
        (
            cd "${src}"
            tar \
                --exclude="__pycache__" \
                --exclude="*/__pycache__" \
                --exclude="*.pyc" \
                -cf - \
                "${REQUIRED_PATHS[@]}"
        ) | (
            cd "${dest}"
            tar -xf -
        )
    fi

    find "${dest}" -type d -name "__pycache__" -prune -exec rm -rf {} + 2>/dev/null || true
    find "${dest}" -type f -name "*.pyc" -delete 2>/dev/null || true
    mkdir -p "${dest}/workspace"

    echo "  Installed for ${label}: ${dest}"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --target) TARGET="${2:-}"; shift 2 ;;
        --project-dir) PROJECT_DIR="${2:-}"; shift 2 ;;
        --skill-name) SKILL_NAME="${2:-}"; shift 2 ;;
        --repo-url) REPO_URL="${2:-}"; shift 2 ;;
        --source) SOURCE_MODE="${2:-}"; shift 2 ;;
        --repo-path) REPO_PATH="${2:-}"; shift 2 ;;
        --install-deps) INSTALL_DEPS=1; shift ;;
        --force) FORCE=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

VALID_TARGETS="claude codex antigravity cursor windsurf continue global project all"
if ! echo "${VALID_TARGETS}" | grep -qw "${TARGET}"; then
    echo "Error: invalid --target: ${TARGET}" >&2
    echo "Valid targets: ${VALID_TARGETS}" >&2
    exit 1
fi

if [[ "${SOURCE_MODE}" != "auto" && "${SOURCE_MODE}" != "local" && "${SOURCE_MODE}" != "remote" ]]; then
    echo "Error: invalid --source: ${SOURCE_MODE}" >&2
    exit 1
fi

require_cmd bash
require_cmd python3

SCRIPT_PATH="${BASH_SOURCE[0]-$0}"
SCRIPT_DIR="$(cd "$(dirname "${SCRIPT_PATH}")" && pwd)"
SRC_DIR=""
SHOULD_CLONE=0

if [[ -n "${REPO_PATH}" ]]; then
    SRC_DIR="$(resolve_dir "${REPO_PATH}")"
    echo "Using repo path source: ${SRC_DIR}"
elif [[ "${SOURCE_MODE}" == "local" ]]; then
    SRC_DIR="${SCRIPT_DIR}"
    echo "Using local source: ${SRC_DIR}"
elif [[ "${SOURCE_MODE}" == "remote" ]]; then
    SHOULD_CLONE=1
elif [[ -f "${SCRIPT_DIR}/SKILL.md" ]]; then
    SRC_DIR="${SCRIPT_DIR}"
    echo "Using local source: ${SRC_DIR}"
else
    SHOULD_CLONE=1
fi

if [[ "${SHOULD_CLONE}" -eq 1 ]]; then
    require_cmd git
    TEMP_DIR="$(mktemp -d)"
    echo "Cloning source repo: ${REPO_URL}"
    if ! git clone --depth 1 "${REPO_URL}" "${TEMP_DIR}/repo" >/dev/null 2>&1; then
        echo "Error: failed to clone: ${REPO_URL}" >&2
        exit 1
    fi
    SRC_DIR="${TEMP_DIR}/repo"
    echo "Using remote source: ${SRC_DIR}"
fi

if [[ ! -f "${SRC_DIR}/SKILL.md" ]]; then
    echo "Error: SKILL.md not found in source: ${SRC_DIR}" >&2
    exit 1
fi

echo ""
echo "Installing Code-VulnScan Skill"
echo "Target:     ${TARGET}"
echo "Skill name: ${SKILL_NAME}"
echo ""

# ── Install per target ────────────────────────────────────────────────────

install_claude() {
    local dest="${HOME}/.claude/skills/${SKILL_NAME}"
    copy_skill "${SRC_DIR}" "${dest}" "Claude Code (~/.claude/skills/)"
}

install_codex() {
    local codex_root="${CODEX_HOME:-${HOME}/.codex}"
    local dest="${codex_root}/skills/${SKILL_NAME}"
    copy_skill "${SRC_DIR}" "${dest}" "Codex (~/.codex/skills/)"
}

install_antigravity() {
    local dest="${PROJECT_DIR}/.agent/skills/${SKILL_NAME}"
    copy_skill "${SRC_DIR}" "${dest}" "Antigravity (.agent/skills/)"
}

install_cursor() {
    local dest="${PROJECT_DIR}/.cursor/skills/${SKILL_NAME}"
    copy_skill "${SRC_DIR}" "${dest}" "Cursor (.cursor/skills/)"
    # Also append a reference to .cursorrules if it exists or create a stub
    local rules_file="${PROJECT_DIR}/.cursorrules"
    if [[ -f "${rules_file}" ]]; then
        if ! grep -q "code-vulnscan" "${rules_file}" 2>/dev/null; then
            echo "" >> "${rules_file}"
            echo "# Code-VulnScan skill installed at .cursor/skills/${SKILL_NAME}" >> "${rules_file}"
            echo "# To run: ask 'vulnscan scan .' or 'find vulnerabilities in this codebase'" >> "${rules_file}"
        fi
    fi
}

install_windsurf() {
    local dest="${PROJECT_DIR}/.windsurf/skills/${SKILL_NAME}"
    copy_skill "${SRC_DIR}" "${dest}" "Windsurf (.windsurf/skills/)"
    local rules_file="${PROJECT_DIR}/.windsurfrules"
    if [[ -f "${rules_file}" ]]; then
        if ! grep -q "code-vulnscan" "${rules_file}" 2>/dev/null; then
            echo "" >> "${rules_file}"
            echo "# Code-VulnScan skill installed at .windsurf/skills/${SKILL_NAME}" >> "${rules_file}"
        fi
    fi
}

install_continue() {
    local dest="${PROJECT_DIR}/.continue/skills/${SKILL_NAME}"
    copy_skill "${SRC_DIR}" "${dest}" "Continue.dev (.continue/skills/)"
}

case "${TARGET}" in
    claude) install_claude ;;
    codex) install_codex ;;
    antigravity) install_antigravity ;;
    cursor) install_cursor ;;
    windsurf) install_windsurf ;;
    continue) install_continue ;;
    global)
        install_claude
        install_codex
        ;;
    project)
        install_antigravity
        install_cursor
        install_windsurf
        install_continue
        ;;
    all)
        install_claude
        install_codex
        install_antigravity
        install_cursor
        install_windsurf
        install_continue
        ;;
esac

# ── Python dependencies ───────────────────────────────────────────────────

if [[ "${INSTALL_DEPS}" -eq 1 ]]; then
    echo ""
    echo "Installing Python dependencies..."
    if [[ -f "${SRC_DIR}/requirements.txt" ]] && python3 -m pip install --user -r "${SRC_DIR}/requirements.txt" 2>/dev/null; then
        echo "Dependencies installed."
    else
        echo "No additional dependencies required (stdlib only for core scripts)."
    fi
fi

echo ""
echo "Install complete."
echo ""
echo "Next steps:"
echo "  1. Restart your IDE/agent session to pick up the skill."
echo "  2. Ask: 'vulnscan scan /path/to/your/codebase'"
echo "  3. Or:  'find security vulnerabilities in this project'"
