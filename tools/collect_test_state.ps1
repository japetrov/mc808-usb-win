# Read-only Windows queries. Writes only a timestamped local evidence JSON.
# Does not stage, install, start, stop, sign or modify any driver or policy.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$evidenceRoot = Join-Path $repoRoot 'build/hardware-evidence'
New-Item -ItemType Directory -Path $evidenceRoot -Force | Out-Null
$observations = [ordered]@{
    CapturedUtc = [DateTime]::UtcNow.ToString('o')
    Purpose = 'Observation only; not authorization or proof of loadability'
    UserReported = @{
        MemoryIntegrity = 'Off, reported 2026-11-06; verify observed state below'
        SignatureEnforcement = 'Startup Settings override; current effectiveness unknown'
        TestMode = 'Not enabled, reported 2026-11-06'
    }
}
function Read-Observation {
    param([string]$Name, [scriptblock]$Query)
    try {
        $observations[$Name] = @{ Status = 'Observed'; Value = @(& $Query) }
    } catch {
        $observations[$Name] = @{ Status = 'Unknown'; Error = $_.Exception.Message }
    }
}
function Read-NativeInformation {
    param([string]$File, [string[]]$Arguments)
    $start = [System.Diagnostics.ProcessStartInfo]::new($File)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    # Arguments here are fixed read-only switches, never user-built shell text.
    $start.Arguments = $Arguments -join ' '
    $process = [System.Diagnostics.Process]::Start($start)
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $process.WaitForExit()
    $text = $stdout.Result + $stderr.Result
    $exitCode = $process.ExitCode
    $process.Dispose()
    if ($exitCode -ne 0) { throw "Read-only query failed ($exitCode): $text" }
    $text
}
Read-Observation 'AdministratorToken' {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
    $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}
Read-Observation 'BootPolicy' {
    Read-NativeInformation (Join-Path $env:SystemRoot 'System32/bcdedit.exe') @('/enum')
}
Read-Observation 'RecoveryEnvironment' {
    Read-NativeInformation (Join-Path $env:SystemRoot 'System32/reagentc.exe') @('/info')
}
Read-Observation 'SystemVolumeEncryption' {
    Get-BitLockerVolume -MountPoint $env:SystemDrive |
        Select-Object MountPoint, VolumeStatus, ProtectionStatus, EncryptionPercentage
}
Read-Observation 'SecureBootRegistry' {
    (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State').UEFISecureBootEnabled
}
Read-Observation 'Windows' {
    Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' |
        Select-Object ProductName, DisplayVersion, CurrentBuildNumber, UBR
}
Read-Observation 'DeviceGuard' {
    $guard = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard
    [pscustomobject]@{
        VirtualizationBasedSecurityStatus = $guard.VirtualizationBasedSecurityStatus
        SecurityServicesConfigured = $guard.SecurityServicesConfigured
        SecurityServicesRunning = $guard.SecurityServicesRunning
        HvciRunning = 2 -in $guard.SecurityServicesRunning
    }
}
Read-Observation 'SecureBoot' { Confirm-SecureBootUEFI }
Read-Observation 'Mc808Device' {
    Get-CimInstance Win32_PnPEntity |
        Where-Object { $_.PNPDeviceID -like 'USB\VID_0582&PID_00A9*' } |
        Select-Object Name, Status, ConfigManagerErrorCode, Service
}
Read-Observation 'RolandService' {
    Get-CimInstance Win32_SystemDriver -Filter "Name='RDID1064'" |
        Select-Object Name, State, StartMode, PathName
}
Read-Observation 'InstalledRolandPackage' {
    Get-CimInstance Win32_PnPSignedDriver |
        Where-Object { $_.DeviceID -like 'USB\VID_0582&PID_00A9*' } |
        Select-Object DeviceName, InfName, DriverVersion, DriverDate, IsSigned, DriverProviderName
}
Read-Observation 'OriginalAndCandidate' {
    foreach ($relative in @('Files/64bit/Files/RDWM1064.SYS', 'build/experimental/RDWM1064.experimental.sys')) {
        $driverPath = Join-Path $repoRoot $relative
        if (-not (Test-Path -LiteralPath $driverPath -PathType Leaf)) {
            [pscustomobject]@{ File = $relative; Present = $false }
            continue
        }
        $signature = Get-AuthenticodeSignature -LiteralPath $driverPath
        [pscustomobject]@{
            File = $relative
            Present = $true
            Sha256 = (Get-FileHash -LiteralPath $driverPath -Algorithm SHA256).Hash
            SignatureStatus = [string]$signature.Status
            SignatureMessage = $signature.StatusMessage
            SignerSubject = $signature.SignerCertificate.Subject
        }
    }
}
$outputFile = Join-Path $evidenceRoot ('state-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ') + '-' + [Guid]::NewGuid().ToString('N') + '.json')
$observations | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $outputFile -Encoding utf8
Write-Output $outputFile
Write-Output 'Observation complete. Unknown queries are not evidence that a protection is disabled.'
