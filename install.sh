#!/usr/bin/env bash

set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/Bhanunamikaze/Code-VulnScan-Skill.git}"
SKILL_NAME="code-vulnscan"
TARGET="claude"
TARGET_EXPLICIT=0
PROJECT_DIR="$(pwd)"
PROJECT_DIR_EXPLICIT=0
FORCE=0
INSTALL_DEPS=0
ONLINE_MODE=0
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

Each IDE target installs the skill in that IDE's native format:
  claude / codex / antigravity  →  skills/ directory  (native skill support)
  cursor                        →  .cursor/rules/*.mdc  (Cursor MDC rules format)
  windsurf                      →  .windsurf/rules/*.md  (Windsurf rules format)
  copilot                       →  .github/copilot-instructions.md
  cline                         →  .clinerules  (Cline project instructions)
  continue                      →  .continue/prompts/vulnscan.prompt  (slash command)

Usage:
  bash install.sh [options]

Options:
  --target <target>
      Install target (default: claude). Valid targets:
        claude       → ~/.claude/skills/code-vulnscan
        codex        → ~/.codex/skills/code-vulnscan
        antigravity  → <project>/.agent/skills/code-vulnscan
        cursor       → <project>/.cursor/rules/code-vulnscan.mdc
        windsurf     → <project>/.windsurf/rules/code-vulnscan.md
        continue     → <project>/.continue/prompts/vulnscan.prompt
        copilot      → <project>/.github/copilot-instructions.md
        cline        → <project>/.clinerules
        global       → claude + codex (user-wide)
        project      → antigravity + cursor + windsurf + continue + copilot + cline
        all          → global + project (every target)

  --project-dir <path>         Project directory for project-local installs (default: cwd)
  --skill-name <name>          Installed folder name for skills-dir targets (default: code-vulnscan)
  --repo-url <url>             Git URL for remote source installs
  --source <auto|local|remote> Source mode (default: auto)
  --repo-path <path>           Use a specific local checkout as the install source
  --online                     Fetch latest release archive instead of cloning.
                               When no --target is supplied, defaults to --target all.
  --install-deps               Install optional Python dependencies
  --force                      Overwrite an existing installed skill
  -h, --help                   Show this help

Examples:
  bash install.sh --target claude
  bash install.sh --target global
  bash install.sh --target project --project-dir /path/to/your/project
  bash install.sh --target cursor  --project-dir /path/to/your/project
  bash install.sh --target all     --project-dir /path/to/your/project
  bash install.sh --online

Safer remote install:
  curl -fsSLO https://raw.githubusercontent.com/Bhanunamikaze/Code-VulnScan-Skill/main/install.sh
  curl -fsSLO https://raw.githubusercontent.com/Bhanunamikaze/Code-VulnScan-Skill/main/install.sh.sha256
  sha256sum -c install.sh.sha256
  bash install.sh --target claude
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

# ── Skills-directory copy (Claude / Codex / Antigravity) ─────────────────────

copy_skill() {
    local src="$1"
    local dest="$2"
    local label="$3"

    if [[ -e "${dest}" && "${FORCE}" -ne 1 ]]; then
        echo "  Warning: ${label} target already exists: ${dest}" >&2
        echo "  Use --force to overwrite." >&2
        return 1
    fi

    for required_path in "${REQUIRED_PATHS[@]}"; do
        if [[ ! -e "${src}/${required_path}" ]]; then
            echo "  Error: required skill path not found: ${src}/${required_path}" >&2
            return 1
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

# ── Root resolution helpers ───────────────────────────────────────────────────

global_root_for_tool() {
    local tool="$1"
    case "${tool}" in
        claude)      printf '%s\n' "${CLAUDE_HOME:-${HOME}/.claude}" ;;
        codex)       printf '%s\n' "${CODEX_HOME:-${HOME}/.codex}" ;;
        antigravity) printf '%s\n' "${HOME}/.gemini/antigravity" ;;
        *)           return 1 ;;
    esac
}

workspace_root_for_tool() {
    local tool="$1"
    case "${tool}" in
        antigravity)
            if [[ "${TARGET}" == "antigravity" || "${PROJECT_DIR_EXPLICIT}" -eq 1 || -d "${PROJECT_DIR}/.agent" ]]; then
                printf '%s\n' "${PROJECT_DIR}/.agent"
                return 0
            fi
            ;;
        claude)
            if [[ "${PROJECT_DIR_EXPLICIT}" -eq 1 && -d "${PROJECT_DIR}/.claude" ]]; then
                printf '%s\n' "${PROJECT_DIR}/.claude"
                return 0
            fi
            ;;
        codex)
            if [[ "${PROJECT_DIR_EXPLICIT}" -eq 1 && -d "${PROJECT_DIR}/.codex" ]]; then
                printf '%s\n' "${PROJECT_DIR}/.codex"
                return 0
            fi
            ;;
    esac
    return 1
}

install_tool_auto() {
    local tool="$1"
    local install_root="" label=""
    if install_root="$(workspace_root_for_tool "${tool}")"; then
        label="${tool}-local"
    else
        install_root="$(global_root_for_tool "${tool}")"
        label="${tool}-global"
    fi
    copy_skill "${SRC_DIR}" "${install_root}/skills/${SKILL_NAME}" "${label}"
}

install_tool_global() {
    local tool="$1"
    local global_root
    global_root="$(global_root_for_tool "${tool}")"
    copy_skill "${SRC_DIR}" "${global_root}/skills/${SKILL_NAME}" "${tool}-global"
}

# ── IDE-native format installers ─────────────────────────────────────────────

# Shared invocation summary used across IDE-specific formats
_skill_invocation_text() {
    cat <<'SKILL_CONTENT'
# Code-VulnScan — Vulnerability Scanning Skill

You have access to the Code-VulnScan security scanning skill.

## When to activate

Activate whenever the user asks to:
- Find vulnerabilities / security issues / bugs in code
- Run a security audit or penetration test review
- Check for secrets, hardcoded credentials, or API keys
- Scan dependencies for known CVEs
- Review authentication, cryptography, or authorization logic
- Check for SQL injection, XSS, SSRF, path traversal, or other OWASP Top 10 issues
- Analyse taint flow / data flow from user input to dangerous sinks
- Review IaC files (Dockerfile, Kubernetes, Terraform, GitHub Actions) for misconfigurations

## Invocation

| Command | Description |
|---------|-------------|
| `vulnscan scan <path>`    | Full codebase vulnerability scan |
| `vulnscan taint <file>`   | Taint-flow analysis on a single file |
| `vulnscan secrets <path>` | Secret / credential detection |
| `vulnscan deps <path>`    | Dependency CVE check |
| `vulnscan config <path>`  | Configuration & IaC security audit |
| `vulnscan report`         | Generate Markdown / SARIF / JSON report |
| `vulnscan status`         | Show current scan progress |

## Skill file

Read **SKILL.md** for the full multi-phase workflow and sub-skill instructions.
SKILL_CONTENT
}

# Cursor — .cursor/rules/code-vulnscan.mdc  (MDC frontmatter format)
install_cursor() {
    local rules_dir="${PROJECT_DIR}/.cursor/rules"
    local mdc_file="${rules_dir}/code-vulnscan.mdc"

    if [[ -f "${mdc_file}" && "${FORCE}" -ne 1 ]]; then
        echo "  Warning: Cursor rule already exists: ${mdc_file} (use --force to overwrite)"
        return 0
    fi

    mkdir -p "${rules_dir}"

    {
        cat <<'MDC_HEADER'
---
description: "Code-VulnScan — vulnerability scanning skill. Activate when the user asks to find security vulnerabilities, audit code, scan for secrets/CVEs, or review auth/crypto logic."
globs: []
alwaysApply: false
---
MDC_HEADER
        _skill_invocation_text
    } > "${mdc_file}"

    echo "  Installed Cursor rule: ${mdc_file}"

    # Also copy full skill for reference (scripts / sub-skills / resources)
    copy_skill "${SRC_DIR}" "${PROJECT_DIR}/.cursor/skills/${SKILL_NAME}" "Cursor (.cursor/skills/)" || true
}

# Windsurf — .windsurf/rules/code-vulnscan.md  (rules directory format)
install_windsurf() {
    local rules_dir="${PROJECT_DIR}/.windsurf/rules"
    local rule_file="${rules_dir}/code-vulnscan.md"

    if [[ -f "${rule_file}" && "${FORCE}" -ne 1 ]]; then
        echo "  Warning: Windsurf rule already exists: ${rule_file} (use --force to overwrite)"
        return 0
    fi

    mkdir -p "${rules_dir}"
    _skill_invocation_text > "${rule_file}"

    echo "  Installed Windsurf rule: ${rule_file}"

    copy_skill "${SRC_DIR}" "${PROJECT_DIR}/.windsurf/skills/${SKILL_NAME}" "Windsurf (.windsurf/skills/)" || true
}

# Continue.dev — .continue/prompts/vulnscan.prompt  (slash command format)
install_continue() {
    local prompts_dir="${PROJECT_DIR}/.continue/prompts"
    local prompt_file="${prompts_dir}/vulnscan.prompt"

    if [[ -f "${prompt_file}" && "${FORCE}" -ne 1 ]]; then
        echo "  Warning: Continue prompt already exists: ${prompt_file} (use --force to overwrite)"
        return 0
    fi

    mkdir -p "${prompts_dir}"

    cat > "${prompt_file}" <<'PROMPT_FILE'
name: vulnscan
description: Run Code-VulnScan vulnerability analysis on the selected code or codebase
---
You have the Code-VulnScan vulnerability scanning skill loaded.

{{{ input }}}

Use the full Code-VulnScan workflow:
1. Identify the scan target from the user's request
2. Run taint-flow analysis from user-controlled sources to dangerous sinks
3. Check input validation, business logic, auth, crypto, secrets, dependencies, and IaC
4. Apply the three-pass false-positive elimination protocol
5. Report only Confirmed and Likely findings with evidence chains and remediation

Read SKILL.md for the complete multi-phase workflow.
PROMPT_FILE

    echo "  Installed Continue.dev prompt: ${prompt_file}"

    copy_skill "${SRC_DIR}" "${PROJECT_DIR}/.continue/skills/${SKILL_NAME}" "Continue.dev (.continue/skills/)" || true
}

# GitHub Copilot — .github/copilot-instructions.md
install_copilot() {
    local github_dir="${PROJECT_DIR}/.github"
    local instructions_file="${github_dir}/copilot-instructions.md"
    mkdir -p "${github_dir}"

    local skill_block
    skill_block="$(
        printf '---\n\n'
        _skill_invocation_text
    )"

    if [[ -f "${instructions_file}" ]]; then
        if grep -q "Code-VulnScan" "${instructions_file}" 2>/dev/null; then
            echo "  GitHub Copilot instructions already contain Code-VulnScan (skipping)"
        else
            printf '\n%s\n' "${skill_block}" >> "${instructions_file}"
            echo "  Updated GitHub Copilot instructions: ${instructions_file}"
        fi
    else
        printf '%s\n' "${skill_block}" > "${instructions_file}"
        echo "  Created GitHub Copilot instructions: ${instructions_file}"
    fi

    copy_skill "${SRC_DIR}" "${github_dir}/skills/${SKILL_NAME}" "GitHub Copilot (.github/skills/)" || true
}

# Cline — .clinerules  (project-level instruction file)
install_cline() {
    local rules_file="${PROJECT_DIR}/.clinerules"
    local marker="<!-- code-vulnscan-skill -->"

    if [[ -f "${rules_file}" ]] && grep -q "code-vulnscan-skill" "${rules_file}" 2>/dev/null; then
        if [[ "${FORCE}" -ne 1 ]]; then
            echo "  Warning: .clinerules already contains Code-VulnScan entry (use --force to overwrite)"
            return 0
        fi
        # Remove old block and rewrite
        python3 -c "
import re, sys
text = open('${rules_file}').read()
text = re.sub(r'<!-- code-vulnscan-skill -->.*?<!-- /code-vulnscan-skill -->\n?', '', text, flags=re.DOTALL)
open('${rules_file}', 'w').write(text)
"
    fi

    {
        printf '\n%s\n' "${marker}"
        _skill_invocation_text
        printf '<!-- /code-vulnscan-skill -->\n'
    } >> "${rules_file}"

    echo "  Updated .clinerules: ${rules_file}"

    copy_skill "${SRC_DIR}" "${PROJECT_DIR}/.cline/skills/${SKILL_NAME}" "Cline (.cline/skills/)" || true
}

# ── Argument parsing ──────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)         TARGET="${2:-}"; TARGET_EXPLICIT=1; shift 2 ;;
        --project-dir)    PROJECT_DIR="${2:-}"; PROJECT_DIR_EXPLICIT=1; shift 2 ;;
        --skill-name)     SKILL_NAME="${2:-}"; shift 2 ;;
        --repo-url)       REPO_URL="${2:-}"; shift 2 ;;
        --source)         SOURCE_MODE="${2:-}"; shift 2 ;;
        --repo-path)      REPO_PATH="${2:-}"; shift 2 ;;
        --install-deps)   INSTALL_DEPS=1; shift ;;
        --online)         ONLINE_MODE=1; FORCE=1; shift ;;
        --force)          FORCE=1; shift ;;
        -h|--help)        usage; exit 0 ;;
        *)                echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

VALID_TARGETS="claude codex antigravity cursor windsurf continue copilot cline global project all"
if ! echo "${VALID_TARGETS}" | grep -qw "${TARGET}"; then
    echo "Error: invalid --target: ${TARGET}" >&2
    echo "Valid targets: ${VALID_TARGETS}" >&2
    exit 1
fi

if [[ "${SOURCE_MODE}" != "auto" && "${SOURCE_MODE}" != "local" && "${SOURCE_MODE}" != "remote" ]]; then
    echo "Error: invalid --source: ${SOURCE_MODE}" >&2
    exit 1
fi

if [[ "${ONLINE_MODE}" -eq 1 && "${TARGET_EXPLICIT}" -ne 1 ]]; then
    TARGET="all"
fi

require_cmd bash
require_cmd python3

SCRIPT_PATH="${BASH_SOURCE[0]-$0}"
SCRIPT_DIR="$(cd "$(dirname "${SCRIPT_PATH}")" && pwd)"
SRC_DIR=""
SHOULD_CLONE=0

# ── Source resolution ─────────────────────────────────────────────────────────

if [[ "${ONLINE_MODE}" -eq 1 ]]; then
    require_cmd curl
    require_cmd tar
    echo "Fetching latest release tag..."
    LATEST_TAG=$(curl -sL "https://api.github.com/repos/Bhanunamikaze/Code-VulnScan-Skill/releases/latest" \
        | grep '"tag_name":' | head -n 1 | sed -E 's/.*"([^"]+)".*/\1/' || true)
    TEMP_DIR="$(mktemp -d)"
    if [[ -z "${LATEST_TAG}" || "${LATEST_TAG}" == "null" ]]; then
        echo "Could not determine latest tag, falling back to main branch archive..."
        curl -sL "https://github.com/Bhanunamikaze/Code-VulnScan-Skill/archive/refs/heads/main.tar.gz" \
            | tar -xz -C "${TEMP_DIR}" --strip-components=1
    else
        echo "Downloading latest tag package: ${LATEST_TAG}"
        curl -sL "https://github.com/Bhanunamikaze/Code-VulnScan-Skill/archive/refs/tags/${LATEST_TAG}.tar.gz" \
            | tar -xz -C "${TEMP_DIR}" --strip-components=1
    fi
    SRC_DIR="${TEMP_DIR}"
    echo "Using downloaded package source: ${SRC_DIR}"
elif [[ -n "${REPO_PATH}" ]]; then
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
        echo "Error: failed to clone source repo: ${REPO_URL}" >&2
        echo "Tip: pass --repo-path <local-path> or --online to avoid cloning." >&2
        exit 1
    fi
    SRC_DIR="${TEMP_DIR}/repo"
    echo "Using remote source: ${SRC_DIR}"
fi

if [[ ! -f "${SRC_DIR}/SKILL.md" ]]; then
    echo "Error: SKILL.md not found in source directory: ${SRC_DIR}" >&2
    exit 1
fi

echo ""
echo "Installing Code-VulnScan Skill"
echo "Target:     ${TARGET}"
echo "Skill name: ${SKILL_NAME}"
echo ""

# ── Install per target ────────────────────────────────────────────────────────

case "${TARGET}" in
    claude)      install_tool_auto "claude" ;;
    codex)       install_tool_auto "codex" ;;
    antigravity) install_tool_auto "antigravity" ;;
    cursor)      install_cursor ;;
    windsurf)    install_windsurf ;;
    continue)    install_continue ;;
    copilot)     install_copilot ;;
    cline)       install_cline ;;
    global)
        install_tool_global "claude"
        install_tool_global "codex"
        ;;
    project)
        install_tool_auto "antigravity" || true
        install_cursor                  || true
        install_windsurf                || true
        install_continue                || true
        install_copilot                 || true
        install_cline                   || true
        ;;
    all)
        install_tool_global "claude"    || true
        install_tool_global "codex"     || true
        install_tool_auto "antigravity" || true
        install_cursor                  || true
        install_windsurf                || true
        install_continue                || true
        install_copilot                 || true
        install_cline                   || true
        ;;
esac

# ── Python dependencies ───────────────────────────────────────────────────────

if [[ "${INSTALL_DEPS}" -eq 1 ]]; then
    echo ""
    echo "Installing Python dependencies..."
    if [[ -f "${SRC_DIR}/requirements.txt" ]] && python3 -m pip install --user -r "${SRC_DIR}/requirements.txt" 2>/dev/null; then
        echo "Installed dependencies from requirements.txt"
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
