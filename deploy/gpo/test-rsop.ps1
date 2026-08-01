# SPDX-License-Identifier: MIT
# Copyright (c) 2026 netscope contributors
$ErrorActionPreference = "Continue"

Write-Host "[+] Auditing Netscope Group Policy Resultant Set of Policy (RSoP)..." -ForegroundColor Green

$regKey = "HKLM:\SOFTWARE\Policies\Netscope\Agent"

if (-not (Test-Path $regKey)) {
    Write-Host "[-] No Netscope GPO settings found under $regKey" -ForegroundColor Yellow
    exit 0
}

Write-Host "[+] Applied Group Policy Settings:" -ForegroundColor Cyan
Get-ItemProperty -Path $regKey | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSDrive, PSProvider | Format-List

$updatesKey = "HKLM:\SOFTWARE\Policies\Netscope\Agent\Updates"
if (Test-Path $updatesKey) {
    Write-Host "[+] Applied Update Policy Settings:" -ForegroundColor Cyan
    Get-ItemProperty -Path $updatesKey | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSDrive, PSProvider | Format-List
}
