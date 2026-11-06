# Mathematical CMS verification only. Does not build trust or import certificates.
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Catalog, [Parameter(Mandatory)][string]$Certificate)
$ErrorActionPreference = 'Stop'
$cms = [System.Security.Cryptography.Pkcs.SignedCms]::new()
$cms.Decode([IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Catalog)))
if ($cms.SignerInfos.Count -ne 1) { throw 'Expected exactly one catalog signer.' }
$signer = $cms.SignerInfos[0]
if ($signer.DigestAlgorithm.Value -ne '2.16.840.1.101.3.4.2.1') { throw 'Expected SHA256 catalog signature.' }
$publicBytes = [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Certificate))
if ([Convert]::ToHexString($signer.Certificate.RawData) -ne [Convert]::ToHexString($publicBytes)) {
    throw 'Catalog signer differs from the exported driver-signing certificate.'
}
$cms.CheckSignature($true) # verifySignatureOnly: deliberately no machine trust changes.
[ordered]@{
    CatalogSignatureValid = $true
    SameCertificateAsDriver = $true
    CertificateThumbprint = $signer.Certificate.Thumbprint
    WindowsTrustVerified = $false
    KernelPolicyVerified = $false
} | ConvertTo-Json
