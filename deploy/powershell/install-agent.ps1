# SPDX-License-Identifier: MIT
# Copyright (c) 2026 netscope contributors
param(
    [Parameter(Mandatory=$true)]
    [string]$ServerUrl,
    [Parameter(Mandatory=$true)]
    [string]$EnrollmentToken,
    [string]$SensorGroup = "Default",
    [string]$MsiPath = ".\netscope-agent-0.2.0-x64.msi"
)

$ErrorActionPreference = "Stop"

Write-Host "[+] Installing Netscope Sensor Agent..." -ForegroundColor Green
Write-Host "    Server: $ServerUrl"
Write-Host "    Group: $SensorGroup"

$arguments = @(
    "/i", "`"$MsiPath`"",
    "/qn", "/norestart",
    "NETSCOPE_SERVER_URL=`"$ServerUrl`"",
    "NETSCOPE_ENROLLMENT_TOKEN=`"$EnrollmentToken`"",
    "NETSCOPE_SENSOR_GROUP=`"$SensorGroup`"",
    "NETSCOPE_AUTOSTART=`"1`"",
    "/L*V", "`"$env:TEMP\netscope-install.log`""
)

$process = Start-Process -FilePath "msiexec.exe" -ArgumentList $arguments -Wait -PassThru

if ($process.ExitCode -eq 0) {
    Write-Host "[+] Netscope Agent installed successfully." -ForegroundColor Green
} else {
    Write-Error "[-] MSI installation failed with exit code $($process.ExitCode). Check $env:TEMP\netscope-install.log"
}
