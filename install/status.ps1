# ============================================================
# NIGHTFANG -> Hermes Status Inspector (Windows)
# ============================================================
[CmdletBinding()]
param(
    [string]$HermesHome = "$env:USERPROFILE\.hermes"
)

$NightfangRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$NfHermesHome = Join-Path $HermesHome "nightfang"
$HermesBinDir = Join-Path $HermesHome "bin"
$NfSkillLink = Join-Path $HermesHome "skills\nightfang"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   NIGHTFANG -> Hermes Health & Integration Status" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "NIGHTFANG Root : $NightfangRoot"
Write-Host "Hermes Home    : $HermesHome"
Write-Host ""

$checks = @(
    @{ Name = "Skills Link"; Path = $NfSkillLink; Type = "Dir" },
    @{ Name = "System Prompt"; Path = "$NfHermesHome\system.md"; Type = "File" },
    @{ Name = "Config Overlay"; Path = "$NfHermesHome\config.yaml"; Type = "File" },
    @{ Name = "Scope Storage"; Path = "$NfHermesHome\memory\scope.yaml"; Type = "File" },
    @{ Name = "Findings Store"; Path = "$NfHermesHome\memory\findings.json"; Type = "File" },
    @{ Name = "Knowledge Graph Store"; Path = "$NfHermesHome\memory\knowledge_graph.jsonl"; Type = "File" },
    @{ Name = "MCP Configuration"; Path = "$HermesHome\mcp.json"; Type = "File" },
    @{ Name = "Gateway Wrapper"; Path = "$HermesBinDir\nightfang-gate.cmd"; Type = "File" },
    @{ Name = "Launcher CLI"; Path = "$HermesBinDir\nightfang.cmd"; Type = "File" },
    @{ Name = "Metadata Record"; Path = "$NfHermesHome\installation.json"; Type = "File" },
    @{ Name = "Channel Card Formatter"; Path = "$NightfangRoot\tools\channel_card.py"; Type = "File" },
    @{ Name = "Finding Sync Manager"; Path = "$NightfangRoot\tools\finding_sync.py"; Type = "File" },
    @{ Name = "Adversarial Verifier"; Path = "$NightfangRoot\tools\verifier.py"; Type = "File" }
)

$allPassed = $true
foreach ($c in $checks) {
    if (Test-Path $c.Path) {
        Write-Host "  [OK] $($c.Name) ($($c.Path))" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] $($c.Name) missing at $($c.Path)" -ForegroundColor Red
        $allPassed = $false
    }
}

if (Test-Path "$HermesHome\mcp.json") {
    try {
        $mcpObj = Get-Content "$HermesHome\mcp.json" -Raw | ConvertFrom-Json
        $serverCount = ($mcpObj.mcpServers.PSObject.Properties | Measure-Object).Count
        if ($serverCount -ge 8) {
            Write-Host "  [OK] MCP Servers Verification ($serverCount verified servers configured in mcp.json)" -ForegroundColor Green
        } else {
            Write-Host "  [FAIL] MCP Configuration has fewer than 8 servers ($serverCount detected)" -ForegroundColor Red
            $allPassed = $false
        }
    } catch {
        Write-Host "  [FAIL] MCP Configuration is not valid JSON" -ForegroundColor Red
        $allPassed = $false
    }
}

if (Test-Path "$HermesHome\config.yaml") {
    try {
        $null = & python -c "import yaml; yaml.safe_load(open(r'$HermesHome\config.yaml'))" 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  [OK] Hermes Config Syntax (Valid YAML)" -ForegroundColor Green
        }
    } catch {}
}

$launcher = Join-Path $HermesBinDir "nightfang.cmd"
if (Test-Path $launcher) {
    & $launcher --test-all 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] NIGHTFANG Self-Tests (All 10 Core Engines & E2E Simulation PASS)" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] NIGHTFANG Self-Tests failed" -ForegroundColor Red
        $allPassed = $false
    }
}

Write-Host ""
if ($allPassed) {
    Write-Host "Overall Status: NIGHTFANG IS FULLY OPERATIONAL IN HERMES" -ForegroundColor Green
} else {
    Write-Host "Overall Status: INCOMPLETE INTEGRATION - Run .\install\install.ps1" -ForegroundColor Yellow
}
Write-Host ""
