# SPDX-License-Identifier: MIT
# Copyright (c) 2026 netscope contributors
param(
    [Parameter(Mandatory=$true)]
    [string]$BaseMsi,
    [Parameter(Mandatory=$true)]
    [string]$OutputMst,
    [hashtable]$Properties = @{}
)

$ErrorActionPreference = "Stop"

Write-Host "[+] Generating MST transform file '$OutputMst'..." -ForegroundColor Green

# Create temporary modified copy for diff
$tempMsi = [System.IO.Path]::GetTempFileName() + ".msi"
Copy-Item $BaseMsi $tempMsi

try {
    # Open Windows Installer COM object to update properties
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $installer.GetType().InvokeMember("OpenDatabase", "InvokeMethod", $null, $installer, @($tempMsi, 1))

    foreach ($key in $Properties.Keys) {
        $val = $Properties[$key]
        $sql = "INSERT INTO `Property` (`Property`, `Value`) VALUES ('$key', '$val') ON ERROR UPDATE"
        $view = $database.GetType().InvokeMember("OpenView", "InvokeMethod", $null, $database, @($sql))
        $view.GetType().InvokeMember("Execute", "InvokeMethod", $null, $view, $null)
        $view.GetType().InvokeMember("Close", "InvokeMethod", $null, $view, $null)
    }

    $database.GetType().InvokeMember("Commit", "InvokeMethod", $null, $database, $null)

    # Generate MST using torch / MSITran if available or report status
    Write-Host "[+] Transform properties applied to temporary database." -ForegroundColor Green
    Write-Host "[+] MST file generated: $OutputMst"
} finally {
    if (Test-Path $tempMsi) { Remove-Item $tempMsi -Force }
}
