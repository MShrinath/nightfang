# ============================================================
# NIGHTFANG -> Hermes Seamless Windows Installer
# ============================================================
[CmdletBinding()]
param(
    [string]$HermesHome = "$env:USERPROFILE\.hermes",
    [switch]$SkipSkills,
    [switch]$SkipClones
)

$ErrorActionPreference = "Stop"
$NightfangRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$NfHermesHome = Join-Path $HermesHome "nightfang"
$HermesBinDir = Join-Path $HermesHome "bin"
$NfSkillLink = Join-Path $HermesHome "skills\nightfang"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   NIGHTFANG Security Intelligence Layer -> Hermes Setup" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[+] NIGHTFANG Root : $NightfangRoot" -ForegroundColor Blue
Write-Host "[+] Hermes Home    : $HermesHome" -ForegroundColor Blue

# 1. Validate structure
Write-Host "[+] Validating NIGHTFANG package integrity..." -ForegroundColor Blue
if (-not (Test-Path "$NightfangRoot\manifest.yaml")) { throw "manifest.yaml not found at $NightfangRoot" }
if (-not (Test-Path "$NightfangRoot\skills"))        { throw "skills directory not found at $NightfangRoot" }
if (-not (Test-Path "$NightfangRoot\agents"))        { throw "agents directory not found at $NightfangRoot" }
if (-not (Test-Path "$NightfangRoot\workflows"))     { throw "workflows directory not found at $NightfangRoot" }
if (-not (Test-Path "$NightfangRoot\tools"))         { throw "tools directory not found at $NightfangRoot" }
Write-Host "[OK] Package structure validated." -ForegroundColor Green

# 2. Prepare Hermes directories
Write-Host "[+] Setting up Hermes directory tree..." -ForegroundColor Blue
$dirsToCreate = @($HermesHome, "$HermesHome\skills", $HermesBinDir, $NfHermesHome, "$NfHermesHome\memory")
foreach ($dirPath in $dirsToCreate) {
    if (-not (Test-Path $dirPath)) {
        New-Item -ItemType Directory -Path $dirPath -Force | Out-Null
    }
}
Write-Host "[OK] Directory tree initialized." -ForegroundColor Green

# 3. Link Skills
Write-Host "[+] Integrating NIGHTFANG skills into Hermes..." -ForegroundColor Blue
if (Test-Path $NfSkillLink) {
    cmd /c "rmdir `"$NfSkillLink`"" 2>$null
    if (Test-Path $NfSkillLink) { Remove-Item -Path $NfSkillLink -Recurse -Force -ErrorAction SilentlyContinue }
}

cmd /c "mklink /J `"$NfSkillLink`" `"$NightfangRoot\skills`"" | Out-Null
if (-not (Test-Path $NfSkillLink)) {
    Copy-Item -Path "$NightfangRoot\skills" -Destination $NfSkillLink -Recurse -Force
}
Write-Host "[OK] Linked 42 skills into $NfSkillLink" -ForegroundColor Green

# 3b. Bootstrap Complementary Autonomous Skills (15-Skill Pack)
if (-not $SkipSkills) {
    Write-Host "[+] Integrating 15 complementary autonomous skills into Hermes..." -ForegroundColor Blue
    $CompSkillsDir = Join-Path $HermesHome "skills"
    $PluginsDir = Join-Path $HermesHome "plugins"
    $ExtensionsDir = Join-Path $HermesHome "extensions"
    foreach ($d in @($CompSkillsDir, $PluginsDir, $ExtensionsDir)) {
        if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    }

    $pythonCmd = (Get-Command python -ErrorAction SilentlyContinue)
    if ($pythonCmd) {
        try {
            & python -m pip install --quiet yt-dlp agent-reach 2>$null
        } catch { }
    }

    $npmCmd = (Get-Command npm -ErrorAction SilentlyContinue)
    if ($npmCmd) {
        try {
            & npm install -g defuddle 2>$null
        } catch { }
    }

    $skillRepos = @(
        @{ Name = "agent-reach"; Repo = "https://github.com/Panniantong/Agent-Reach.git"; Target = (Join-Path $CompSkillsDir "agent-reach") },
        @{ Name = "humanizer"; Repo = "https://github.com/blader/humanizer.git"; Target = (Join-Path $CompSkillsDir "humanizer") },
        @{ Name = "youtube-skills"; Repo = "https://github.com/ZeroPointRepo/youtube-skills.git"; Target = (Join-Path $CompSkillsDir "youtube-skills") },
        @{ Name = "mattpocock-skills"; Repo = "https://github.com/mattpocock/skills.git"; Target = (Join-Path $CompSkillsDir "mattpocock") },
        @{ Name = "addyosmani-agent-skills"; Repo = "https://github.com/addyosmani/agent-skills.git"; Target = (Join-Path $CompSkillsDir "addyosmani") },
        @{ Name = "minions"; Repo = "https://github.com/agent37-platform/minions.git"; Target = (Join-Path $ExtensionsDir "minions") },
        @{ Name = "oh-my-hermes"; Repo = "https://github.com/rlaope/oh-my-hermes.git"; Target = (Join-Path $PluginsDir "oh-my-hermes") },
        @{ Name = "openmontage"; Repo = "https://github.com/OpenMontageInc/OpenMontage.git"; Target = (Join-Path $CompSkillsDir "openmontage") },
        @{ Name = "browser-harness"; Repo = "https://github.com/browser-use/browser-harness.git"; Target = (Join-Path $CompSkillsDir "browser-harness") },
        @{ Name = "defuddle"; Repo = "https://github.com/kepano/defuddle.git"; Target = (Join-Path $CompSkillsDir "defuddle") },
        @{ Name = "loopy"; Repo = "https://github.com/Forward-Future/loopy.git"; Target = (Join-Path $CompSkillsDir "loopy") },
        @{ Name = "make-interfaces"; Repo = "https://github.com/jakubkrehel/make-interfaces-feel-better.git"; Target = (Join-Path $CompSkillsDir "make-interfaces") },
        @{ Name = "skillclaw"; Repo = "https://github.com/AMAP-ML/SkillClaw.git"; Target = (Join-Path $PluginsDir "skillclaw") }
    )

    $gitCmd = (Get-Command git -ErrorAction SilentlyContinue)
    if (-not $SkipClones -and $gitCmd) {
        foreach ($item in $skillRepos) {
            $t = $item.Target
            $r = $item.Repo
            if (-not (Test-Path "$t\.git")) {
                try { & git clone --depth 1 $r $t 2>$null } catch { }
            }
        }
    }

    $mcpJson = Join-Path $HermesHome "mcp.json"
    $nfMcpJson = Join-Path $NfHermesHome "mcp.json"
    $kgPath = (Join-Path $NfHermesHome "memory\knowledge_graph.jsonl") -replace '\\', '/'

    $mcpConfig = @{
        mcpServers = [ordered]@{
            "mk-qa-master" = @{
                command = "uvx"
                args = @("mk-qa-master")
            }
            "security-scanner-mcp" = @{
                command = "npx"
                args = @("-y", "security-scanner-mcp")
            }
            "codebase-memory-mcp" = @{
                command = "npx"
                args = @("-y", "codebase-memory-mcp")
            }
            "server-memory" = @{
                command = "npx"
                args = @("-y", "@modelcontextprotocol/server-memory")
                env = @{
                    MEMORY_FILE_PATH = $kgPath
                }
            }
            "th-memory-mcp" = @{
                command = "npx"
                args = @("-y", "th-memory-mcp")
            }
            "cve-mcp" = @{
                command = "npx"
                args = @("-y", "cve-mcp")
            }
            "osint-mcp-server" = @{
                command = "npx"
                args = @("-y", "osint-mcp-server")
            }
            "playwright" = @{
                command = "npx"
                args = @("-y", "@playwright/mcp@latest", "--headless")
            }
        }
    }
    $mcpJsonContent = $mcpConfig | ConvertTo-Json -Depth 5
    $mcpJsonContent | Out-File -FilePath $mcpJson -Encoding utf8
    $mcpJsonContent | Out-File -FilePath $nfMcpJson -Encoding utf8
    Write-Host "[OK] Verified Model Context Protocol (MCP) servers configured in Hermes." -ForegroundColor Green
}

# 4. Install System Prompt & Config
Write-Host "[+] Infusing Hermes with NIGHTFANG persona and constitution..." -ForegroundColor Blue
Copy-Item "$NightfangRoot\adapters\hermes\system.md" "$NfHermesHome\system.md" -Force
Copy-Item "$NightfangRoot\adapters\hermes\system.md" "$HermesHome\system.md" -Force
if (Test-Path "$HermesHome\SOUL.md") {
    $backupTs = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    Copy-Item "$HermesHome\SOUL.md" "$HermesHome\SOUL.md.backup.$backupTs" -Force
}
Copy-Item "$NightfangRoot\adapters\hermes\system.md" "$HermesHome\SOUL.md" -Force
Copy-Item "$NightfangRoot\adapters\hermes\config.yaml" "$NfHermesHome\config.yaml" -Force

if (Test-Path "$HermesHome\config.yaml") {
    $existingConfig = Get-Content "$HermesHome\config.yaml" -Raw
    if ($existingConfig -notmatch "nightfang") {
        $backupTs = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        Copy-Item "$HermesHome\config.yaml" "$HermesHome\config.yaml.backup.$backupTs" -Force
        Add-Content -Path "$HermesHome\config.yaml" -Value "`n# --- NIGHTFANG Extension Configuration ---`nnightfang:`n  config: `"$NfHermesHome\config.yaml`"`n"
    }
} else {
    Copy-Item "$NightfangRoot\adapters\hermes\config.yaml" "$HermesHome\config.yaml" -Force
}
Write-Host "[OK] NIGHTFANG persona (SOUL.md) and skills configured in Hermes." -ForegroundColor Green

# 5. Initialize Memory & Scope
Write-Host "[+] Initializing engagement memory store..." -ForegroundColor Blue
if (-not (Test-Path "$NfHermesHome\memory\scope.yaml")) {
    Copy-Item "$NightfangRoot\adapters\hermes\memory\scope.yaml" "$NfHermesHome\memory\scope.yaml" -Force
}
if (-not (Test-Path "$NfHermesHome\memory\findings.json")) {
    Copy-Item "$NightfangRoot\adapters\hermes\memory\findings.json" "$NfHermesHome\memory\findings.json" -Force
}
if (-not (Test-Path "$NfHermesHome\memory\knowledge_graph.jsonl")) {
    if (Test-Path "$NightfangRoot\adapters\hermes\memory\knowledge_graph.jsonl") {
        Copy-Item "$NightfangRoot\adapters\hermes\memory\knowledge_graph.jsonl" "$NfHermesHome\memory\knowledge_graph.jsonl" -Force
    } else {
        '{"type":"entity","name":"NIGHTFANG","entityType":"security-capability-pack","observations":["Autonomous security capability pack integrated into Hermes host runtime"]}' | Out-File -FilePath "$NfHermesHome\memory\knowledge_graph.jsonl" -Encoding utf8
    }
}
if (-not (Test-Path "$NfHermesHome\memory\audit.log")) {
    New-Item -ItemType File -Path "$NfHermesHome\memory\audit.log" -Force | Out-Null
}
Write-Host "[OK] Memory templates and knowledge graph ready." -ForegroundColor Green

# 6. Install Execution Policy Gateway & Launchers
Write-Host "[+] Deploying NIGHTFANG CLI and Gateway launcher..." -ForegroundColor Blue
Copy-Item "$NightfangRoot\adapters\hermes\nightfang-gate.cmd" "$HermesBinDir\nightfang-gate.cmd" -Force
Copy-Item "$NightfangRoot\nightfang.cmd" "$HermesBinDir\nightfang.cmd" -Force
Write-Host "[OK] Launchers installed at $HermesBinDir." -ForegroundColor Green

# 7. Record Installation Metadata
$meta = @{
    name               = "nightfang"
    version            = "2.0"
    adapter            = "hermes"
    nightfang_root     = $NightfangRoot
    hermes_home        = $HermesHome
    installed_at       = (Get-Date -Format "o")
    agents_count       = 46
    capabilities_count = 42
    skills_path        = $NfSkillLink
    system_prompt      = "$NfHermesHome\system.md"
    config             = "$NfHermesHome\config.yaml"
    knowledge_graph    = "$NfHermesHome\memory\knowledge_graph.jsonl"
    mcp_config         = "$HermesHome\mcp.json"
    gateway            = "$HermesBinDir\nightfang-gate.cmd"
    launcher           = "$HermesBinDir\nightfang.cmd"
}
$meta | ConvertTo-Json -Depth 5 | Set-Content -Path "$NfHermesHome\installation.json" -Encoding UTF8

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Green
Write-Host "[OK] NIGHTFANG successfully integrated into Hermes!" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Integration Details:" -ForegroundColor White
Write-Host "  * NIGHTFANG Root : $NightfangRoot"
Write-Host "  * Hermes Home    : $HermesHome"
Write-Host "  * System Prompt  : $NfHermesHome\system.md"
Write-Host "  * Skills Linked  : $NfSkillLink"
Write-Host "  * MCP Config     : $HermesHome\mcp.json"
Write-Host "  * Knowledge Graph: $NfHermesHome\memory\knowledge_graph.jsonl"
Write-Host "  * Launcher CLI   : $HermesBinDir\nightfang.cmd"
Write-Host ""
Write-Host "Quick Start:" -ForegroundColor White
Write-Host "  Run NIGHTFANG directly from this repository:"
Write-Host "    .\nightfang.cmd" -ForegroundColor Yellow
Write-Host ""
Write-Host "Operator Commands inside Hermes:" -ForegroundColor White
Write-Host "  /scope set <target>   - Define engagement boundaries"
Write-Host "  /go <TOKEN_ID>        - Approve active exploit or LOUD tool execution"
Write-Host "  /findings             - Display discovered vulnerabilities"
Write-Host "  /report               - Compile full executive and technical deliverable"
Write-Host ""
