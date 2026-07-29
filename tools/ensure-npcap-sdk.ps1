param(
    [string]$SdkUrl = "https://npcap.com/dist/npcap-sdk-1.13.zip",
    [string]$OutDir = (Join-Path (Split-Path $PSScriptRoot -Parent) "npcap-sdk")
)

$zipPath = Join-Path $env:TEMP "npcap-sdk.zip"
$libDir  = Join-Path $OutDir "Lib\x64"

if (Test-Path (Join-Path $libDir "wpcap.lib")) {
    Write-Host "✓ Npcap SDK already present at $OutDir"
    exit 0
}

Write-Host "↓ Downloading Npcap SDK from $SdkUrl ..."
try {
    Invoke-WebRequest -Uri $SdkUrl -OutFile $zipPath -UseBasicParsing
} catch {
    Write-Error "Failed to download Npcap SDK from $SdkUrl"
    exit 1
}

Write-Host "↓ Extracting to $OutDir ..."
try {
    Expand-Archive -Path $zipPath -DestinationPath $OutDir -Force
} catch {
    Write-Error "Failed to extract Npcap SDK to $OutDir"
    exit 1
}

Remove-Item $zipPath -Force -ErrorAction SilentlyContinue

if (Test-Path (Join-Path $libDir "wpcap.lib")) {
    Write-Host "✓ Npcap SDK ready at $OutDir"
    Write-Host "  (LIBPCAP_LIBDIR automatically resolved by .cargo/config.toml)"
    exit 0
} else {
    Write-Error "Extraction did not produce expected path: $libDir\wpcap.lib"
    exit 1
}
