# ============================================================
# NIGHTFANG -> Hermes Seamless Windows Installer
# ============================================================
[CmdletBinding()]
param(
    [string]$HermesHome = "$env:USERPROFILE\.hermes"
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
Write-Host "[OK] Linked 31 skills into $NfSkillLink" -ForegroundColor Green

# 4. Install System Prompt & Config
Write-Host "[+] Infusing Hermes with NIGHTFANG persona and constitution..." -ForegroundColor Blue
Copy-Item "$NightfangRoot\adapters\hermes\system.md" "$NfHermesHome\system.md" -Force
Copy-Item "$NightfangRoot\adapters\hermes\system.md" "$HermesHome\system.md" -Force
Copy-Item "$NightfangRoot\adapters\hermes\config.yaml" "$NfHermesHome\config.yaml" -Force

if (Test-Path "$HermesHome\config.yaml") {
    $backupTs = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    Copy-Item "$HermesHome\config.yaml" "$HermesHome\config.yaml.backup.$backupTs" -Force
}
Copy-Item "$NightfangRoot\adapters\hermes\config.yaml" "$HermesHome\config.yaml" -Force
Write-Host "[OK] NIGHTFANG installed as default Hermes system context." -ForegroundColor Green

# 5. Initialize Memory & Scope
Write-Host "[+] Initializing engagement memory store..." -ForegroundColor Blue
if (-not (Test-Path "$NfHermesHome\memory\scope.yaml")) {
    Copy-Item "$NightfangRoot\adapters\hermes\memory\scope.yaml" "$NfHermesHome\memory\scope.yaml" -Force
}
if (-not (Test-Path "$NfHermesHome\memory\findings.json")) {
    Copy-Item "$NightfangRoot\adapters\hermes\memory\findings.json" "$NfHermesHome\memory\findings.json" -Force
}
if (-not (Test-Path "$NfHermesHome\memory\audit.log")) {
    New-Item -ItemType File -Path "$NfHermesHome\memory\audit.log" -Force | Out-Null
}
Write-Host "[OK] Memory templates ready." -ForegroundColor Green

# 6. Install Execution Policy Gateway & Launchers
Write-Host "[+] Deploying NIGHTFANG CLI and Gateway launcher..." -ForegroundColor Blue
Copy-Item "$NightfangRoot\adapters\hermes\nightfang-gate.cmd" "$HermesBinDir\nightfang-gate.cmd" -Force
Copy-Item "$NightfangRoot\adapters\hermes\nightfang.cmd" "$HermesBinDir\nightfang.cmd" -Force
Copy-Item "$NightfangRoot\adapters\hermes\nightfang.cmd" "$NightfangRoot\nightfang.cmd" -Force
Write-Host "[OK] Launchers installed at $HermesBinDir and repo root." -ForegroundColor Green

# 7. Record Installation Metadata
$meta = @{
    name               = "nightfang"
    version            = "2.0"
    adapter            = "hermes"
    nightfang_root     = $NightfangRoot
    hermes_home        = $HermesHome
    installed_at       = (Get-Date -Format "o")
    agents_count       = 37
    capabilities_count = 33
    skills_path        = $NfSkillLink
    system_prompt      = "$NfHermesHome\system.md"
    config             = "$NfHermesHome\config.yaml"
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
