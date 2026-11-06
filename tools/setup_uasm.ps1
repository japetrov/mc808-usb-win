# Fetch a pinned portable assembler into this repository's ignored tools folder.
# No system installation, PATH change, driver operation or security-setting change.
$ErrorActionPreference = 'Stop'
$uasmProjectRoot = Split-Path -Parent $PSScriptRoot
$uasmPin = Get-Content -LiteralPath (Join-Path $uasmProjectRoot 'toolchains/uasm-2.57.json') -Raw | ConvertFrom-Json
$uasmToolsRoot = Join-Path $uasmProjectRoot '.tools'
$uasmArchive = Join-Path $uasmToolsRoot 'uasm257_x64.zip'
$uasmExtractRoot = [IO.Path]::GetFullPath((Join-Path $uasmToolsRoot 'uasm-2.57'))
$uasmExecutable = Join-Path $uasmExtractRoot 'uasm64.exe'
New-Item -ItemType Directory -Path $uasmToolsRoot -Force | Out-Null
if (-not (Test-Path -LiteralPath $uasmArchive)) {
    Invoke-WebRequest -Uri $uasmPin.archive_url -OutFile $uasmArchive
}
if ((Get-FileHash -LiteralPath $uasmArchive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $uasmPin.archive_sha256) {
    throw 'UASM archive fingerprint mismatch; refusing extraction.'
}
if (-not (Test-Path -LiteralPath $uasmExecutable)) {
    $uasmZip = [IO.Compression.ZipFile]::OpenRead($uasmArchive)
    try {
        $uasmPrefix = $uasmExtractRoot + [IO.Path]::DirectorySeparatorChar
        foreach ($uasmEntry in $uasmZip.Entries) {
            $uasmTarget = [IO.Path]::GetFullPath([IO.Path]::Combine($uasmExtractRoot, $uasmEntry.FullName))
            if (-not $uasmTarget.StartsWith($uasmPrefix, [StringComparison]::OrdinalIgnoreCase)) {
                throw 'UASM archive entry escapes the intended extraction directory.'
            }
        }
    } finally {
        $uasmZip.Dispose()
    }
    [IO.Compression.ZipFile]::ExtractToDirectory($uasmArchive, $uasmExtractRoot, $true)
}
if ((Get-FileHash -LiteralPath $uasmExecutable -Algorithm SHA256).Hash.ToLowerInvariant() -ne $uasmPin.executable_sha256) {
    throw 'UASM executable fingerprint mismatch; refusing verification.'
}
Write-Output 'Pinned portable UASM is ready. Run tools/verify_native_shims.py to assemble and compare the source.'
