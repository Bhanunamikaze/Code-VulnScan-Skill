#!/usr/bin/env pwsh

$ErrorActionPreference = 'Stop'

$REPO_URL        = if ($env:REPO_URL) { $env:REPO_URL } else { 'https://github.com/Bhanunamikaze/Code-VulnScan-Skill.git' }
$SKILL_NAME      = 'code-vulnscan'
$TARGET          = 'claude'
$TARGET_EXPLICIT = $false
$PROJECT_DIR     = (Get-Location).Path
$PROJECT_DIR_EXPLICIT = $false
$FORCE           = $false
$INSTALL_DEPS    = $false
$ONLINE_MODE     = $false
$SOURCE_MODE     = 'auto'
$REPO_PATH       = ''
$TEMP_DIR        = $null

$REQUIRED_PATHS  = @('SKILL.md', 'scripts', 'sub-skills', 'resources')

# Shared invocation block written into every IDE-native format file
$SKILL_INVOCATION_TEXT = @'
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
'@

function Show-Usage {
@'
Code-VulnScan Skill Installer (Windows / PowerShell)

Each IDE target installs the skill in that IDE's native format:
  claude / codex / antigravity  ->  skills/ directory  (native skill support)
  cursor                        ->  .cursor\rules\code-vulnscan.mdc  (MDC rules)
  windsurf                      ->  .windsurf\rules\code-vulnscan.md
  copilot                       ->  .github\copilot-instructions.md
  cline                         ->  .clinerules
  continue                      ->  .continue\prompts\vulnscan.prompt

Usage:
  pwsh ./install.ps1 [options]

Options:
  --target <target>
      Install target (default: claude). Valid targets:
        claude       ->  ~\.claude\skills\code-vulnscan
        codex        ->  ~\.codex\skills\code-vulnscan
        antigravity  ->  <project>\.agent\skills\code-vulnscan
        cursor       ->  <project>\.cursor\rules\code-vulnscan.mdc
        windsurf     ->  <project>\.windsurf\rules\code-vulnscan.md
        continue     ->  <project>\.continue\prompts\vulnscan.prompt
        copilot      ->  <project>\.github\copilot-instructions.md
        cline        ->  <project>\.clinerules
        global       ->  claude + codex (user-wide)
        project      ->  antigravity + cursor + windsurf + continue + copilot + cline
        all          ->  global + project (every target)

  --project-dir <path>         Project directory for project-local installs (default: cwd)
  --skill-name <name>          Installed folder name for skills-dir targets (default: code-vulnscan)
  --repo-url <url>             Git URL for remote source installs
  --source <auto|local|remote> Source mode (default: auto)
  --repo-path <path>           Use a specific local checkout as the install source
  --online                     Fetch latest release zip instead of cloning.
                               When no --target is supplied, defaults to --target all.
  --install-deps               Install optional Python dependencies
  --force                      Overwrite an existing installed skill
  -h, --help                   Show this help

Examples:
  pwsh ./install.ps1 --target claude
  pwsh ./install.ps1 --target global
  pwsh ./install.ps1 --target project --project-dir C:\path\to\your\project
  pwsh ./install.ps1 --target cursor  --project-dir C:\path\to\your\project
  pwsh ./install.ps1 --target all     --project-dir C:\path\to\your\project
  pwsh ./install.ps1 --online

'@ | Write-Host
}

function Require-Cmd {
    param([Parameter(Mandatory = $true)][string]$Cmd)
    if (-not (Get-Command -Name $Cmd -ErrorAction SilentlyContinue)) {
        throw "Error: required command not found: $Cmd"
    }
}

function Resolve-Dir {
    param([Parameter(Mandatory = $true)][string]$Dir)
    if (-not (Test-Path -LiteralPath $Dir -PathType Container)) {
        throw "Error: directory not found: $Dir"
    }
    return (Resolve-Path -LiteralPath $Dir).Path
}

function Invoke-ExternalCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [string[]]$Arguments = @()
    )
    $stdoutPath = [System.IO.Path]::GetTempFileName()
    $stderrPath = [System.IO.Path]::GetTempFileName()
    try {
        $proc = Start-Process -FilePath $Command -ArgumentList $Arguments -Wait -PassThru `
            -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
        $stdout = Get-Content -LiteralPath $stdoutPath -Raw -ErrorAction SilentlyContinue
        $stderr = Get-Content -LiteralPath $stderrPath -Raw -ErrorAction SilentlyContinue
        if (-not [string]::IsNullOrEmpty($stdout)) { [Console]::Out.Write($stdout) }
        if (-not [string]::IsNullOrEmpty($stderr)) { [Console]::Out.Write($stderr) }
        return $proc.ExitCode
    }
    finally {
        Remove-Item -LiteralPath $stdoutPath, $stderrPath -Force -ErrorAction SilentlyContinue
    }
}

# ── Skills-directory copy (Claude / Codex / Antigravity) ─────────────────────

function Copy-Skill {
    param(
        [Parameter(Mandatory = $true)][string]$Src,
        [Parameter(Mandatory = $true)][string]$Dest,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ((Test-Path -LiteralPath $Dest) -and (-not $FORCE)) {
        Write-Warning "  $Label target already exists: $Dest`n  Use --force to overwrite."
        return
    }

    foreach ($req in $REQUIRED_PATHS) {
        $srcPath = Join-Path $Src $req
        if (-not (Test-Path -LiteralPath $srcPath)) {
            throw "Error: required skill path not found: $srcPath"
        }
    }

    $destParent = Split-Path -Path $Dest -Parent
    if (-not (Test-Path -LiteralPath $destParent)) {
        New-Item -ItemType Directory -Path $destParent -Force | Out-Null
    }
    if (Test-Path -LiteralPath $Dest) {
        Remove-Item -LiteralPath $Dest -Recurse -Force
    }
    New-Item -ItemType Directory -Path $Dest -Force | Out-Null

    foreach ($req in $REQUIRED_PATHS) {
        Copy-Item -LiteralPath (Join-Path $Src $req) -Destination (Join-Path $Dest $req) -Recurse -Force
    }

    Get-ChildItem -Path $Dest -Recurse -Directory -Filter '__pycache__' |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path $Dest -Recurse -File -Filter '*.pyc' |
        Remove-Item -Force -ErrorAction SilentlyContinue

    New-Item -ItemType Directory -Path (Join-Path $Dest 'workspace') -Force | Out-Null
    Write-Host "  Installed for ${Label}: $Dest"
}

# ── Root resolution helpers ───────────────────────────────────────────────────

function Get-GlobalRootForTool {
    param([Parameter(Mandatory = $true)][string]$Tool)
    switch ($Tool) {
        'claude'      { return if ($env:CLAUDE_HOME) { $env:CLAUDE_HOME } else { Join-Path $HOME '.claude' } }
        'codex'       { return if ($env:CODEX_HOME)  { $env:CODEX_HOME  } else { Join-Path $HOME '.codex'  } }
        'antigravity' { return Join-Path $HOME '.gemini\antigravity' }
        default       { throw "Error: unsupported tool: $Tool" }
    }
}

function Get-WorkspaceRootForTool {
    param([Parameter(Mandatory = $true)][string]$Tool)
    switch ($Tool) {
        'antigravity' {
            if ($TARGET -eq 'antigravity' -or $PROJECT_DIR_EXPLICIT -or
                (Test-Path -LiteralPath (Join-Path $PROJECT_DIR '.agent') -PathType Container)) {
                return (Join-Path $PROJECT_DIR '.agent')
            }
        }
        'claude' {
            if ($PROJECT_DIR_EXPLICIT -and
                (Test-Path -LiteralPath (Join-Path $PROJECT_DIR '.claude') -PathType Container)) {
                return (Join-Path $PROJECT_DIR '.claude')
            }
        }
        'codex' {
            if ($PROJECT_DIR_EXPLICIT -and
                (Test-Path -LiteralPath (Join-Path $PROJECT_DIR '.codex') -PathType Container)) {
                return (Join-Path $PROJECT_DIR '.codex')
            }
        }
    }
    return $null
}

function Install-ToolAuto {
    param(
        [Parameter(Mandatory = $true)][string]$Src,
        [Parameter(Mandatory = $true)][string]$Tool,
        [Parameter(Mandatory = $true)][string]$SkillName
    )
    $wsRoot = Get-WorkspaceRootForTool -Tool $Tool
    if ($wsRoot) {
        $installRoot = $wsRoot
        $label = "${Tool}-local"
    }
    else {
        $installRoot = Get-GlobalRootForTool -Tool $Tool
        $label = "${Tool}-global"
    }
    $dest = Join-Path (Join-Path $installRoot 'skills') $SkillName
    Copy-Skill -Src $Src -Dest $dest -Label $label
}

function Install-ToolGlobal {
    param(
        [Parameter(Mandatory = $true)][string]$Src,
        [Parameter(Mandatory = $true)][string]$Tool,
        [Parameter(Mandatory = $true)][string]$SkillName
    )
    $installRoot = Get-GlobalRootForTool -Tool $Tool
    $dest = Join-Path (Join-Path $installRoot 'skills') $SkillName
    Copy-Skill -Src $Src -Dest $dest -Label "${Tool}-global"
}

# ── IDE-native format installers ─────────────────────────────────────────────

# Cursor — .cursor\rules\code-vulnscan.mdc  (MDC frontmatter format)
function Install-Cursor {
    param([Parameter(Mandatory = $true)][string]$Src)
    $rulesDir = Join-Path $PROJECT_DIR '.cursor\rules'
    $mdcFile  = Join-Path $rulesDir 'code-vulnscan.mdc'

    if ((Test-Path -LiteralPath $mdcFile -PathType Leaf) -and (-not $FORCE)) {
        Write-Warning "  Cursor rule already exists: $mdcFile (use --force to overwrite)"
    }
    else {
        New-Item -ItemType Directory -Path $rulesDir -Force | Out-Null
        $header = @'
---
description: "Code-VulnScan — vulnerability scanning skill. Activate when the user asks to find security vulnerabilities, audit code, scan for secrets/CVEs, or review auth/crypto logic."
globs: []
alwaysApply: false
---

'@
        Set-Content -LiteralPath $mdcFile -Value ($header + $SKILL_INVOCATION_TEXT)
        Write-Host "  Installed Cursor rule: $mdcFile"
    }

    $dest = Join-Path (Join-Path $PROJECT_DIR '.cursor\skills') $SKILL_NAME
    try { Copy-Skill -Src $Src -Dest $dest -Label 'Cursor (.cursor\skills\)' } catch { Write-Warning "Skipped skill copy: $_" }
}

# Windsurf — .windsurf\rules\code-vulnscan.md
function Install-Windsurf {
    param([Parameter(Mandatory = $true)][string]$Src)
    $rulesDir  = Join-Path $PROJECT_DIR '.windsurf\rules'
    $ruleFile  = Join-Path $rulesDir 'code-vulnscan.md'

    if ((Test-Path -LiteralPath $ruleFile -PathType Leaf) -and (-not $FORCE)) {
        Write-Warning "  Windsurf rule already exists: $ruleFile (use --force to overwrite)"
    }
    else {
        New-Item -ItemType Directory -Path $rulesDir -Force | Out-Null
        Set-Content -LiteralPath $ruleFile -Value $SKILL_INVOCATION_TEXT
        Write-Host "  Installed Windsurf rule: $ruleFile"
    }

    $dest = Join-Path (Join-Path $PROJECT_DIR '.windsurf\skills') $SKILL_NAME
    try { Copy-Skill -Src $Src -Dest $dest -Label 'Windsurf (.windsurf\skills\)' } catch { Write-Warning "Skipped skill copy: $_" }
}

# Continue.dev — .continue\prompts\vulnscan.prompt  (slash command format)
function Install-Continue {
    param([Parameter(Mandatory = $true)][string]$Src)
    $promptsDir = Join-Path $PROJECT_DIR '.continue\prompts'
    $promptFile = Join-Path $promptsDir 'vulnscan.prompt'

    if ((Test-Path -LiteralPath $promptFile -PathType Leaf) -and (-not $FORCE)) {
        Write-Warning "  Continue prompt already exists: $promptFile (use --force to overwrite)"
    }
    else {
        New-Item -ItemType Directory -Path $promptsDir -Force | Out-Null
        $promptContent = @'
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
'@
        Set-Content -LiteralPath $promptFile -Value $promptContent
        Write-Host "  Installed Continue.dev prompt: $promptFile"
    }

    $dest = Join-Path (Join-Path $PROJECT_DIR '.continue\skills') $SKILL_NAME
    try { Copy-Skill -Src $Src -Dest $dest -Label 'Continue.dev (.continue\skills\)' } catch { Write-Warning "Skipped skill copy: $_" }
}

# GitHub Copilot — .github\copilot-instructions.md
function Install-Copilot {
    param([Parameter(Mandatory = $true)][string]$Src)
    $githubDir       = Join-Path $PROJECT_DIR '.github'
    $instructionFile = Join-Path $githubDir 'copilot-instructions.md'
    New-Item -ItemType Directory -Path $githubDir -Force | Out-Null

    if (Test-Path -LiteralPath $instructionFile -PathType Leaf) {
        $existing = Get-Content -LiteralPath $instructionFile -Raw -ErrorAction SilentlyContinue
        if ($existing -like '*Code-VulnScan*') {
            Write-Host "  GitHub Copilot instructions already contain Code-VulnScan (skipping)"
        }
        else {
            Add-Content -LiteralPath $instructionFile -Value ("`n---`n`n" + $SKILL_INVOCATION_TEXT)
            Write-Host "  Updated GitHub Copilot instructions: $instructionFile"
        }
    }
    else {
        Set-Content -LiteralPath $instructionFile -Value $SKILL_INVOCATION_TEXT
        Write-Host "  Created GitHub Copilot instructions: $instructionFile"
    }

    $dest = Join-Path (Join-Path $githubDir 'skills') $SKILL_NAME
    try { Copy-Skill -Src $Src -Dest $dest -Label 'GitHub Copilot (.github\skills\)' } catch { Write-Warning "Skipped skill copy: $_" }
}

# Cline — .clinerules  (project-level instruction file)
function Install-Cline {
    param([Parameter(Mandatory = $true)][string]$Src)
    $rulesFile = Join-Path $PROJECT_DIR '.clinerules'
    $marker    = '<!-- code-vulnscan-skill -->'

    if ((Test-Path -LiteralPath $rulesFile -PathType Leaf) -and
        ((Get-Content -LiteralPath $rulesFile -Raw) -like '*code-vulnscan-skill*')) {
        if (-not $FORCE) {
            Write-Warning "  .clinerules already contains Code-VulnScan (use --force to overwrite)"
        }
        else {
            # Strip old block
            $text = Get-Content -LiteralPath $rulesFile -Raw
            $text = [regex]::Replace($text, '<!-- code-vulnscan-skill -->.*?<!-- /code-vulnscan-skill -->\r?\n?', '', [System.Text.RegularExpressions.RegexOptions]::Singleline)
            Set-Content -LiteralPath $rulesFile -Value $text
        }
    }

    $block = "`n${marker}`n" + $SKILL_INVOCATION_TEXT + "`n<!-- /code-vulnscan-skill -->`n"
    Add-Content -LiteralPath $rulesFile -Value $block
    Write-Host "  Updated .clinerules: $rulesFile"

    $dest = Join-Path (Join-Path $PROJECT_DIR '.cline\skills') $SKILL_NAME
    try { Copy-Skill -Src $Src -Dest $dest -Label 'Cline (.cline\skills\)' } catch { Write-Warning "Skipped skill copy: $_" }
}

# ── Argument parsing ──────────────────────────────────────────────────────────

$idx = 0
while ($idx -lt $args.Count) {
    $arg = $args[$idx]
    switch ($arg) {
        '--target' {
            if (($idx + 1) -ge $args.Count) { throw 'Error: missing value for --target' }
            $TARGET = $args[$idx + 1]; $TARGET_EXPLICIT = $true; $idx += 2; continue
        }
        '--project-dir' {
            if (($idx + 1) -ge $args.Count) { throw 'Error: missing value for --project-dir' }
            $PROJECT_DIR = $args[$idx + 1]; $PROJECT_DIR_EXPLICIT = $true; $idx += 2; continue
        }
        '--skill-name' {
            if (($idx + 1) -ge $args.Count) { throw 'Error: missing value for --skill-name' }
            $SKILL_NAME = $args[$idx + 1]; $idx += 2; continue
        }
        '--repo-url' {
            if (($idx + 1) -ge $args.Count) { throw 'Error: missing value for --repo-url' }
            $REPO_URL = $args[$idx + 1]; $idx += 2; continue
        }
        '--source' {
            if (($idx + 1) -ge $args.Count) { throw 'Error: missing value for --source' }
            $SOURCE_MODE = $args[$idx + 1]; $idx += 2; continue
        }
        '--repo-path' {
            if (($idx + 1) -ge $args.Count) { throw 'Error: missing value for --repo-path' }
            $REPO_PATH = $args[$idx + 1]; $idx += 2; continue
        }
        '--install-deps' { $INSTALL_DEPS = $true; $idx += 1; continue }
        '--online'       { $ONLINE_MODE = $true; $FORCE = $true; $idx += 1; continue }
        '--force'        { $FORCE = $true; $idx += 1; continue }
        '-h'             { Show-Usage; exit 0 }
        '--help'         { Show-Usage; exit 0 }
        default {
            Show-Usage
            throw "Unknown option: $arg"
        }
    }
}

$VALID_TARGETS = @('claude','codex','antigravity','cursor','windsurf','continue','copilot','cline','global','project','all')
if ($TARGET -notin $VALID_TARGETS) {
    throw "Error: invalid --target: $TARGET`nValid targets: $($VALID_TARGETS -join ', ')"
}
if ($SOURCE_MODE -notin @('auto','local','remote')) {
    throw "Error: invalid --source: $SOURCE_MODE"
}
if ($ONLINE_MODE -and (-not $TARGET_EXPLICIT)) { $TARGET = 'all' }

Require-Cmd -Cmd 'python3'

$SCRIPT_DIR  = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$SRC_DIR     = ''
$SHOULD_CLONE = $false

# ── Source resolution ─────────────────────────────────────────────────────────

if ($ONLINE_MODE) {
    Write-Host 'Fetching latest release tag...'
    $zipUrl = ''
    try {
        $releaseInfo = Invoke-RestMethod `
            -Uri 'https://api.github.com/repos/Bhanunamikaze/Code-VulnScan-Skill/releases/latest' `
            -ErrorAction Stop
        $latestTag = $releaseInfo.tag_name
        if ([string]::IsNullOrWhiteSpace($latestTag)) { throw 'Tag empty' }
        Write-Host "Downloading latest tag package: $latestTag"
        $zipUrl = "https://github.com/Bhanunamikaze/Code-VulnScan-Skill/archive/refs/tags/${latestTag}.zip"
    }
    catch {
        Write-Host 'Could not determine latest tag, falling back to main branch archive...'
        $zipUrl = 'https://github.com/Bhanunamikaze/Code-VulnScan-Skill/archive/refs/heads/main.zip'
    }
    $TEMP_DIR = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $TEMP_DIR -Force | Out-Null
    $zipPath = Join-Path $TEMP_DIR 'package.zip'
    Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath
    Expand-Archive -Path $zipPath -DestinationPath $TEMP_DIR -Force
    Remove-Item -Path $zipPath -Force
    $extractedDir = Get-ChildItem -Path $TEMP_DIR -Directory | Select-Object -First 1
    $SRC_DIR = $extractedDir.FullName
    Write-Host "Using downloaded package source: $SRC_DIR"
}
elseif (-not [string]::IsNullOrWhiteSpace($REPO_PATH)) {
    $SRC_DIR = Resolve-Dir -Dir $REPO_PATH
    Write-Host "Using repo path source: $SRC_DIR"
}
elseif ($SOURCE_MODE -eq 'local') {
    $SRC_DIR = $SCRIPT_DIR
    Write-Host "Using local source: $SRC_DIR"
}
elseif ($SOURCE_MODE -eq 'remote') {
    $SHOULD_CLONE = $true
}
elseif (Test-Path -LiteralPath (Join-Path $SCRIPT_DIR 'SKILL.md') -PathType Leaf) {
    $SRC_DIR = $SCRIPT_DIR
    Write-Host "Using local source: $SRC_DIR"
}
else {
    $SHOULD_CLONE = $true
}

try {
    if ($SHOULD_CLONE) {
        Require-Cmd -Cmd 'git'
        $TEMP_DIR = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $TEMP_DIR -Force | Out-Null
        $cloneDir = Join-Path $TEMP_DIR 'repo'
        Write-Host "Cloning source repo: $REPO_URL"
        $ec = Invoke-ExternalCommand -Command 'git' -Arguments @('clone','--depth','1',$REPO_URL,$cloneDir)
        if ($ec -ne 0) {
            throw "Error: failed to clone source repo: $REPO_URL`nTip: pass --repo-path <local-path> or --online to avoid cloning."
        }
        $SRC_DIR = $cloneDir
        Write-Host "Using remote source: $SRC_DIR"
    }

    if (-not (Test-Path -LiteralPath (Join-Path $SRC_DIR 'SKILL.md') -PathType Leaf)) {
        throw "Error: SKILL.md not found in source directory: $SRC_DIR"
    }

    Write-Host ''
    Write-Host 'Installing Code-VulnScan Skill'
    Write-Host "Target:     $TARGET"
    Write-Host "Skill name: $SKILL_NAME"
    Write-Host ''

    # ── Install per target ────────────────────────────────────────────────────

    switch ($TARGET) {
        'claude'      { Install-ToolAuto  -Src $SRC_DIR -Tool 'claude'      -SkillName $SKILL_NAME }
        'codex'       { Install-ToolAuto  -Src $SRC_DIR -Tool 'codex'       -SkillName $SKILL_NAME }
        'antigravity' { Install-ToolAuto  -Src $SRC_DIR -Tool 'antigravity' -SkillName $SKILL_NAME }
        'cursor'      { Install-Cursor    -Src $SRC_DIR }
        'windsurf'    { Install-Windsurf  -Src $SRC_DIR }
        'continue'    { Install-Continue  -Src $SRC_DIR }
        'copilot'     { Install-Copilot   -Src $SRC_DIR }
        'cline'       { Install-Cline     -Src $SRC_DIR }
        'global' {
            try { Install-ToolGlobal -Src $SRC_DIR -Tool 'claude' -SkillName $SKILL_NAME } catch { Write-Warning "Skipped claude-global: $_" }
            try { Install-ToolGlobal -Src $SRC_DIR -Tool 'codex'  -SkillName $SKILL_NAME } catch { Write-Warning "Skipped codex-global: $_" }
        }
        'project' {
            try { Install-ToolAuto -Src $SRC_DIR -Tool 'antigravity' -SkillName $SKILL_NAME } catch { Write-Warning "Skipped antigravity: $_" }
            try { Install-Cursor   -Src $SRC_DIR }                                            catch { Write-Warning "Skipped cursor: $_" }
            try { Install-Windsurf -Src $SRC_DIR }                                            catch { Write-Warning "Skipped windsurf: $_" }
            try { Install-Continue -Src $SRC_DIR }                                            catch { Write-Warning "Skipped continue: $_" }
            try { Install-Copilot  -Src $SRC_DIR }                                            catch { Write-Warning "Skipped copilot: $_" }
            try { Install-Cline    -Src $SRC_DIR }                                            catch { Write-Warning "Skipped cline: $_" }
        }
        'all' {
            try { Install-ToolGlobal -Src $SRC_DIR -Tool 'claude' -SkillName $SKILL_NAME }   catch { Write-Warning "Skipped claude-global: $_" }
            try { Install-ToolGlobal -Src $SRC_DIR -Tool 'codex'  -SkillName $SKILL_NAME }   catch { Write-Warning "Skipped codex-global: $_" }
            try { Install-ToolAuto -Src $SRC_DIR -Tool 'antigravity' -SkillName $SKILL_NAME } catch { Write-Warning "Skipped antigravity: $_" }
            try { Install-Cursor   -Src $SRC_DIR }                                            catch { Write-Warning "Skipped cursor: $_" }
            try { Install-Windsurf -Src $SRC_DIR }                                            catch { Write-Warning "Skipped windsurf: $_" }
            try { Install-Continue -Src $SRC_DIR }                                            catch { Write-Warning "Skipped continue: $_" }
            try { Install-Copilot  -Src $SRC_DIR }                                            catch { Write-Warning "Skipped copilot: $_" }
            try { Install-Cline    -Src $SRC_DIR }                                            catch { Write-Warning "Skipped cline: $_" }
        }
    }

    # ── Python dependencies ───────────────────────────────────────────────────

    if ($INSTALL_DEPS) {
        Write-Host ''
        Write-Host 'Installing Python dependencies...'
        $reqPath = Join-Path $SRC_DIR 'requirements.txt'
        if (Test-Path -LiteralPath $reqPath) {
            $ec = Invoke-ExternalCommand -Command 'python3' -Arguments @('-m','pip','install','--user','-r',$reqPath)
            if ($ec -eq 0) {
                Write-Host 'Installed dependencies from requirements.txt'
            }
            else {
                Write-Warning "Could not auto-install Python dependencies.`nInstall manually: python3 -m pip install --user -r $reqPath"
            }
        }
        else {
            Write-Host 'No additional dependencies required (stdlib only for core scripts).'
        }
    }

    Write-Host ''
    Write-Host 'Install complete.'
    Write-Host ''
    Write-Host 'Next steps:'
    Write-Host '  1. Restart your IDE/agent session to pick up the skill.'
    Write-Host "  2. Ask: 'vulnscan scan /path/to/your/codebase'"
    Write-Host "  3. Or:  'find security vulnerabilities in this project'"
}
finally {
    if ($TEMP_DIR -and (Test-Path -LiteralPath $TEMP_DIR)) {
        Remove-Item -LiteralPath $TEMP_DIR -Recurse -Force -ErrorAction SilentlyContinue
    }
}
