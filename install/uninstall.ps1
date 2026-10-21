# ============================================================
# NIGHTFANG -> Hermes Uninstaller (Windows)
# ============================================================
[CmdletBinding()]
param(
    [string]$HermesHome = "$env:USERPROFILE\.hermes"
)

$NfHermesHome = Join-Path $HermesHome "nightfang"
$HermesBinDir = Join-Path $HermesHome "bin"
$NfSkillLink = Join-Path $HermesHome "skills\nightfang"

Write-Host "Uninstalling NIGHTFANG from Hermes ($HermesHome)..." -ForegroundColor Yellow

if (Test-Path $NfSkillLink) {
    cmd /c "rmdir `"$NfSkillLink`"" 2>$null
    if (Test-Path $NfSkillLink) { Remove-Item -Path $NfSkillLink -Recurse -Force -ErrorAction SilentlyContinue }
    Write-Host "[OK] Removed skills link." -ForegroundColor Green
}

if (Test-Path $NfHermesHome) {
    Remove-Item -Path $NfHermesHome -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "[OK] Removed nightfang directory." -ForegroundColor Green
}

$launcher = Join-Path $HermesBinDir "nightfang.cmd"
if (Test-Path $launcher) { Remove-Item $launcher -Force; Write-Host "[OK] Removed launcher." -ForegroundColor Green }

$gate = Join-Path $HermesBinDir "nightfang-gate.cmd"
if (Test-Path $gate) { Remove-Item $gate -Force; Write-Host "[OK] Removed gateway." -ForegroundColor Green }

$latestBackup = Get-ChildItem -Path $HermesHome -Filter "config.yaml.backup.*" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($latestBackup) {
    Copy-Item $latestBackup.FullName "$HermesHome\config.yaml" -Force
    Remove-Item $latestBackup.FullName -Force
    Write-Host "[OK] Restored original Hermes config.yaml" -ForegroundColor Green
}

Write-Host "[OK] NIGHTFANG uninstalled from Hermes successfully." -ForegroundColor Green
