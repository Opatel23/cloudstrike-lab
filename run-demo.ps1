param(
    [switch]$VerifyOnly,
    [switch]$Foreground
)

$ErrorActionPreference = "Stop"

$projectRoot = $PSScriptRoot
$enginePath = Join-Path $projectRoot "engine"
$reportPath = Join-Path $projectRoot "outputs\demo-report.json"
$dashboardReportPath = Join-Path $projectRoot "dashboard\public\demo-report.json"
$dashboardPath = Join-Path $projectRoot "dashboard"

$pythonCandidates = @()
$bundledPython = Join-Path $env:USERPROFILE ".cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
if (Test-Path $bundledPython) { $pythonCandidates += @{ Exe = $bundledPython; Prefix = @() } }
$pythonCommand = Get-Command python -ErrorAction SilentlyContinue
if ($pythonCommand) { $pythonCandidates += @{ Exe = $pythonCommand.Source; Prefix = @() } }
$pyCommand = Get-Command py -ErrorAction SilentlyContinue
if ($pyCommand) { $pythonCandidates += @{ Exe = $pyCommand.Source; Prefix = @("-3") } }

$selectedPython = $null
foreach ($candidate in $pythonCandidates) {
    & $candidate.Exe @($candidate.Prefix) -c "import sys; assert sys.version_info >= (3, 11)" 2>$null
    if ($LASTEXITCODE -eq 0) { $selectedPython = $candidate; break }
}

if (-not $selectedPython) {
    throw "Python 3.11+ was not found. Install Python, then run this launcher again."
}

$pythonExe = $selectedPython.Exe
$pythonPrefix = $selectedPython.Prefix
$env:PYTHONPATH = $enginePath

Write-Host "[1/3] Generating verified before/after report..." -ForegroundColor Cyan
& $pythonExe @pythonPrefix -m cloudstrike demo --output $reportPath
if ($LASTEXITCODE -ne 0) { throw "The CloudStrike engine demo failed." }

Copy-Item -LiteralPath $reportPath -Destination $dashboardReportPath -Force

Write-Host "[2/3] Dashboard report updated." -ForegroundColor Cyan

$vinext = Join-Path $dashboardPath "node_modules\.bin\vinext.CMD"
if (-not (Test-Path $vinext)) {
    throw "Dashboard dependencies are missing. Run 'pnpm install' inside the dashboard folder once."
}

if ($VerifyOnly) {
    Write-Host "[3/3] Running engine tests..." -ForegroundColor Cyan
    & $pythonExe @pythonPrefix -m unittest discover -s (Join-Path $projectRoot "tests") -v
    if ($LASTEXITCODE -ne 0) { throw "The CloudStrike engine tests failed." }
    Write-Host "Verification complete: all checks passed." -ForegroundColor Green
    return
}

try {
    $runningReport = Invoke-RestMethod -Uri "http://localhost:3000/demo-report.json" -TimeoutSec 2
    if ($runningReport.lab_id -like "cloudstrike-lab-*") {
        Write-Host "[3/3] CloudStrike Lab is already running at http://localhost:3000" -ForegroundColor Green
        Write-Host "Refresh the browser to load the new report." -ForegroundColor DarkGray
        return
    }
} catch {
    # No existing CloudStrike dashboard is listening; start one below.
}

Write-Host "[3/3] Starting CloudStrike Lab at http://localhost:3000" -ForegroundColor Cyan
if ($Foreground) {
    Write-Host "Foreground mode: keep this window open and press Ctrl+C to stop." -ForegroundColor DarkGray
    Push-Location $dashboardPath
    try {
        & $vinext dev
    } finally {
        Pop-Location
    }
    return
}

$logPath = Join-Path $projectRoot "work\dashboard.log"
$errorLogPath = Join-Path $projectRoot "work\dashboard-error.log"
$arguments = "/d /c `"`"$vinext`" dev`""
$serverProcess = Start-Process -FilePath $env:ComSpec -ArgumentList $arguments -WorkingDirectory $dashboardPath -WindowStyle Hidden -RedirectStandardOutput $logPath -RedirectStandardError $errorLogPath -PassThru

$healthy = $false
for ($attempt = 0; $attempt -lt 30; $attempt++) {
    Start-Sleep -Milliseconds 500
    if ($serverProcess.HasExited) { break }
    try {
        $healthReport = Invoke-RestMethod -Uri "http://localhost:3000/demo-report.json" -TimeoutSec 2
        if ($healthReport.lab_id -like "cloudstrike-lab-*") { $healthy = $true; break }
    } catch {
        # The server is still starting.
    }
}

if (-not $healthy) {
    if (-not $serverProcess.HasExited) { Stop-Process -Id $serverProcess.Id -Force }
    $details = if (Test-Path $errorLogPath) { Get-Content -Raw $errorLogPath } else { "No server error log was produced." }
    throw "The dashboard server did not become healthy.`n$details"
}

Write-Host "CloudStrike Lab is ready. You may close this PowerShell window." -ForegroundColor Green
Write-Host "Open or refresh http://localhost:3000" -ForegroundColor Green
