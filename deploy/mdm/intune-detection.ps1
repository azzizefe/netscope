# SPDX-License-Identifier: MIT
# Copyright (c) 2026 netscope contributors
$ErrorActionPreference = "SilentlyContinue"

$targetPath = "$env:ProgramFiles\Netscope\netscope-agent.exe"
$targetMinVersion = [System.Version]"0.2.0.0"

if (Test-Path $targetPath) {
    $versionInfo = (Get-Item $targetPath).VersionInfo
    $installedVersion = [System.Version]$versionInfo.FileVersion

    if ($installedVersion -ge $targetMinVersion) {
        Write-Output "Netscope Agent v$installedVersion is installed."
        exit 0
    }
}

exit 1
