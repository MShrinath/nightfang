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
    @{ Name = "Gateway Wrapper"; Path = "$HermesBinDir\nightfang-gate.cmd"; Type = "File" },
    @{ Name = "Launcher CLI"; Path = "$HermesBinDir\nightfang.cmd"; Type = "File" },
    @{ Name = "Metadata Record"; Path = "$NfHermesHome\installation.json"; Type = "File" }
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

Write-Host ""
if ($allPassed) {
    Write-Host "Overall Status: NIGHTFANG IS FULLY OPERATIONAL IN HERMES" -ForegroundColor Green
} else {
    Write-Host "Overall Status: INCOMPLETE INTEGRATION - Run .\install\install.ps1" -ForegroundColor Yellow
}
Write-Host ""
