
@echo off
cd /d "%~dp0"
title File Integrity Monitor

for /f "usebackq delims=" %%I in (`powershell -NoProfile -STA -Command "Add-Type -AssemblyName System.Windows.Forms; $d = New-Object System.Windows.Forms.FolderBrowserDialog; $d.Description = 'Select the folder to monitor'; if ($d.ShowDialog() -eq 'OK') { $d.SelectedPath }"`) do set "TARGET=%%I"

if not defined TARGET (
    echo No folder selected. Exiting.
    pause
    exit /b
)

echo.
echo Selected folder: "%TARGET%"
echo.

FileIntegrityMonitor.exe monitor "%TARGET%"

echo.
echo Monitoring stopped.
pause
