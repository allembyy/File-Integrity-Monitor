<#
.SYNOPSIS
    Simulates a ransomware attack by creating files, filling them with encrypted-like
    (high-entropy random) bytes, and renaming them with a .locked extension.

.DESCRIPTION
    Safety Guard: This script is hardcoded to execute ONLY inside a disposable folder
    named "TestFolder". Any attempt to run against other directories is rejected.

.PARAMETER TargetPath
    Path to the TestFolder directory (default: .\TestFolder).
#>

[CmdletBinding()]
param(
    [string]$TargetPath = ".\TestFolder"
)

$ErrorActionPreference = "Stop"

# 1. Resolve and validate target path
$resolvedPath = [System.IO.Path]::GetFullPath($TargetPath)
$folderName = Split-Path -Leaf $resolvedPath

if ($folderName -ne "TestFolder") {
    Write-Host ""
    Write-Host "[SAFETY VIOLATION] Execution aborted!" -ForegroundColor Red
    Write-Host "This simulation script is strictly restricted to execute ONLY inside a directory named 'TestFolder'." -ForegroundColor Yellow
    Write-Host "Provided target directory: '$folderName' ($resolvedPath)" -ForegroundColor Yellow
    Write-Host ""
    exit 1
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   RANSOMWARE ATTACK SIMULATION (DISPOSABLE TEST ONLY)    " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Target Folder: $resolvedPath" -ForegroundColor White
Write-Host ""

# 2. Ensure TestFolder exists
if (-not (Test-Path -Path $resolvedPath)) {
    New-Item -ItemType Directory -Path $resolvedPath -Force | Out-Null
    Write-Host "[+] Created directory: $resolvedPath" -ForegroundColor Green
}

# 3. Step 1: Create 50 normal files
Write-Host "[1/3] Generating 50 benign sample files..." -ForegroundColor Yellow
$fileCount = 50

for ($i = 1; $i -le $fileCount; $i++) {
    $fileName = ("doc_{0:D2}.txt" -f $i)
    $filePath = Join-Path $resolvedPath $fileName
    $content = "Document #$i - Confidential project notes, quarterly earnings, and operational reports.`r`n" * 10
    [System.IO.File]::WriteAllText($filePath, $content)
}

Write-Host "      Created $fileCount files successfully." -ForegroundColor Green
Write-Host "      Pausing 1 second for monitor to settle..." -ForegroundColor Gray
Start-Sleep -Seconds 1

# 4. Step 2 & 3: Rewrite files with high-entropy random bytes and rename to .locked
Write-Host "[2/3] Simulating encryption: Overwriting with high-entropy random bytes..." -ForegroundColor Yellow
Write-Host "[3/3] Appending suspicious extension (.locked)..." -ForegroundColor Yellow

$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$randomBuffer = New-Object byte[] 4096

$files = Get-ChildItem -Path $resolvedPath -Filter "*.txt"

foreach ($file in $files) {
    # Fill buffer with cryptographic random bytes (Shannon entropy ~ 7.99)
    $rng.GetBytes($randomBuffer)
    [System.IO.File]::WriteAllBytes($file.FullName, $randomBuffer)

    # Rename to .locked
    $newPath = $file.FullName + ".locked"
    Rename-Item -Path $file.FullName -NewName (Split-Path -Leaf $newPath)
}

Write-Host ""
Write-Host "[OK] Ransomware simulation complete!" -ForegroundColor Green
Write-Host "     $fileCount files were encrypted with random bytes and renamed to .locked." -ForegroundColor White
Write-Host "     Check your File Integrity Monitor console and audit.log for the ALERT." -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
