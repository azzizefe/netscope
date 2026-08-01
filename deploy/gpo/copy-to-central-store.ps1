# SPDX-License-Identifier: MIT
# Copyright (c) 2026 netscope contributors
param(
    [string]$DomainName = $env:USERDNSDOMAIN
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($DomainName)) {
    Write-Error "[-] Domain name not provided and USERDNSDOMAIN is empty."
}

$sysvolPolicyDefs = "\\$DomainName\SYSVOL\$DomainName\Policies\PolicyDefinitions"

Write-Host "[+] Copying Netscope ADMX/ADML templates to SYSVOL Central Store..." -ForegroundColor Green
Write-Host "    Target: $sysvolPolicyDefs"

if (-not (Test-Path $sysvolPolicyDefs)) {
    Write-Host "[*] Creating PolicyDefinitions directory in Central Store..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Path $sysvolPolicyDefs -Force | Out-Null
}

# Copy ADMX
Copy-Item ".\netscope.admx" "$sysvolPolicyDefs\netscope.admx" -Force

# Copy en-US ADML
$enDir = "$sysvolPolicyDefs\en-US"
if (-not (Test-Path $enDir)) { New-Item -ItemType Directory -Path $enDir -Force | Out-Null }
Copy-Item ".\en-US\netscope.adml" "$enDir\netscope.adml" -Force

# Copy tr-TR ADML if exists
if (Test-Path ".\tr-TR\netscope.adml") {
    $trDir = "$sysvolPolicyDefs\tr-TR"
    if (-not (Test-Path $trDir)) { New-Item -ItemType Directory -Path $trDir -Force | Out-Null }
    Copy-Item ".\tr-TR\netscope.adml" "$trDir\netscope.adml" -Force
}

Write-Host "[+] Netscope GPO templates successfully published to Active Directory Central Store." -ForegroundColor Green
