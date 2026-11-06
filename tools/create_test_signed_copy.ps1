# PowerShell 7 required. Offline signing only: no store imports, trust or boot edits.
[CmdletBinding()]
param([switch]$Package)
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -lt 7) { throw 'Run using PowerShell 7 (pwsh).' }
$repoRoot = Split-Path -Parent $PSScriptRoot
$python = Join-Path $repoRoot '.venv-analysis/Scripts/python.exe'
$signTool = Join-Path $repoRoot '.tools/sdk-signing-10.0.26100.6584/signtool.exe'
$unsignedPath = Join-Path $repoRoot 'build/experimental/RDWM1064.experimental.sys'
$toolHash = '010b6a17fd7803e3fc74af1f2e89bbd2bd225aab5f3368f4ed7d7ea4a09eb287'
if ((Get-FileHash -LiteralPath $signTool -Algorithm SHA256).Hash.ToLowerInvariant() -ne $toolHash) {
    throw 'SignTool differs from the pinned SDK version.'
}
$expected = '4d2a21846897975e615d095b94cfb54d39ffb88d61380205e501bbff6d4504c6'
if ((Get-FileHash -LiteralPath $unsignedPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) {
    throw 'Unsigned candidate identity differs.'
}
if ((Get-AuthenticodeSignature -LiteralPath $signTool).Status -ne 'Valid') {
    throw 'Microsoft signing tool signature is not valid.'
}
$outputRoot = Join-Path $repoRoot 'build/test-signed'
if ($Package) {
    $outputRoot = Join-Path $repoRoot 'build/test-signed-packages'
    $inf2cat = Join-Path $repoRoot '.tools/wdk-10.0.26100.6584/inf2cat/Inf2Cat.exe'
    if ((Get-FileHash -LiteralPath $inf2cat -Algorithm SHA256).Hash -ne 'B594728D38B271979367ABC8060A971B8E42422738009BE126710B1F5DD0FCBC') {
        throw 'Inf2Cat differs from the reviewed WDK version.'
    }
}
$folder = Join-Path $outputRoot ([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $folder | Out-Null
# Restrict the folder before any private material is written.
$acl = [System.Security.AccessControl.DirectorySecurity]::new()
$acl.SetAccessRuleProtection($true, $false)
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$rule = [System.Security.AccessControl.FileSystemAccessRule]::new($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
$acl.AddAccessRule($rule)
Set-Acl -LiteralPath $folder -AclObject $acl
$keyFile = Join-Path $folder 'temporary-signing-key.pfx'
$signedPath = Join-Path $folder 'RDWM1064.test-signed.sys'
$publicPath = Join-Path $folder 'MC808-Research-Test.cer'
function Invoke-OfflineTool {
    param([string]$Tool, [string[]]$Arguments, [string]$Log)
    $start = [System.Diagnostics.ProcessStartInfo]::new($Tool)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $process = [System.Diagnostics.Process]::Start($start)
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $process.WaitForExit()
    [IO.File]::WriteAllText((Join-Path $folder $Log), $stdout.Result + $stderr.Result)
    $exitCode = $process.ExitCode
    $process.Dispose()
    $start.ArgumentList.Clear()
    if ($exitCode -ne 0) { throw "Offline tool failed ($exitCode); see $Log." }
}
$rsa = $null
$cert = $null
try {
    $rsa = [System.Security.Cryptography.RSA]::Create(3072)
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=MC808 Unofficial Research Test Only', $rsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $request.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false, $false, 0, $true))
    $request.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
        [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature, $true))
    $eku = [System.Security.Cryptography.OidCollection]::new()
    [void]$eku.Add([System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.3'))
    $request.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($eku, $true))
    $cert = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-10), [DateTimeOffset]::UtcNow.AddDays(90))
    $password = [Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
    [IO.File]::WriteAllBytes($keyFile, $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $password))
    [IO.File]::WriteAllBytes($publicPath, $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
    if ($Package) {
        Invoke-OfflineTool $python @((Join-Path $PSScriptRoot 'verify_signed_package.py'), $folder, '--stage') 'stage.txt'
        $signedPath = Join-Path $folder 'driver/RDWM1064.SYS'
    } else {
        Copy-Item -LiteralPath $unsignedPath -Destination $signedPath
    }
    # No timestamp service or network dependency. SignTool consumes the transient PFX.
    # Password is never logged; it is briefly present in the native process arguments.
    Invoke-OfflineTool $signTool @('sign', '/fd', 'SHA256', '/f', $keyFile, '/p', $password, $signedPath) 'signtool-sign.txt'
    & $python (Join-Path $PSScriptRoot 'verify_test_signature.py') $signedPath $publicPath > (Join-Path $folder 'verification.json')
    if ($LASTEXITCODE -ne 0) { throw 'Offline signature or preservation verification failed.' }
    if ($Package) {
        $driverFolder = Join-Path $folder 'driver'
        $catalogPath = Join-Path $driverFolder 'MC808_EXPERIMENTAL.CAT'
        Invoke-OfflineTool $inf2cat @("/driver:$driverFolder", '/os:10_25H2_X64', '/verbose') 'inf2cat.txt'
        Invoke-OfflineTool $signTool @('sign', '/fd', 'SHA256', '/f', $keyFile, '/p', $password, $catalogPath) 'signtool-catalog-sign.txt'
        & (Join-Path $PSScriptRoot 'verify_catalog_signature.ps1') -Catalog $catalogPath -Certificate $publicPath > (Join-Path $folder 'catalog-signature.json')
        Invoke-OfflineTool $python @((Join-Path $PSScriptRoot 'verify_signed_package.py'), $folder) 'package-verification.json'
    }
    if ((Get-FileHash -LiteralPath $unsignedPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) {
        throw 'Unsigned baseline changed unexpectedly.'
    }
    # A completed manifest must never precede successful private-key cleanup.
    Remove-Item -LiteralPath $keyFile -Force
    if (Test-Path -LiteralPath $keyFile) { throw 'Temporary PFX cleanup failed.' }
    [ordered]@{
        CreatedUtc = [DateTime]::UtcNow.ToString('o')
        CertificateSubject = $cert.Subject
        CertificateThumbprint = $cert.Thumbprint
        CertificateExpires = $cert.NotAfter.ToUniversalTime().ToString('o')
        PrivateKeyRetained = $false
        TrustStoresChanged = $false
        CatalogCreated = [bool]$Package
        DriverInstalledOrLoaded = $false
        BootConfigurationChanged = $false
        Status = 'Offline test signature only; not trusted or approved for loading'
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $folder 'manifest.json') -Encoding utf8
    Write-Output $folder
} finally {
    if (Test-Path -LiteralPath $keyFile) { Remove-Item -LiteralPath $keyFile -Force }
    $password = $null
    if ($null -ne $cert) { $cert.Dispose() }
    if ($null -ne $rsa) { $rsa.Dispose() }
}
