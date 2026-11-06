# Download, patch and test the MC-808 driver

This is an **experimental Windows 11 x64 / 25H2 test procedure**, not a
production driver installer. The INF currently targets workstation build 26200
or later; ARM64 and older Windows builds are outside this guide.
Read [RIGHTS.md](../RIGHTS.md): Roland's terms restrict modification and
redistribution, and this tutorial grants no permission. Obtain your own package
and review its terms. No vendor files or signing certificates are supplied here.

**Known bug:** closing MC-808 Editor before sleep causes communication to fail
after wake/reopen. Leaving it open worked in one test; USB reconnect recovered
the failed case. See [STATUS.md](STATUS.md). Use a recoverable test machine,
preserve important files and keep your BitLocker recovery key accessible from
another device. The build scripts never change machine security or load drivers.

Run commands one at a time and **stop on errors**. Driver trust, boot and device
changes are confined to steps marked **Administrator**. Prerequisite software
installation and the optional session-only script policy are called out below.
Do not run Roland Setup.exe.

## 1. Install the tools

You need Git, PowerShell 7 and Python 3.12. If needed, manually install Git,
PowerShell and uv (which can install Python) using WinGet:

```powershell
winget install --id Git.Git --exact
winget install --id Microsoft.PowerShell --exact
winget install --id astral-sh.uv --exact
```

Review installer prompts. Close the terminal and open **PowerShell 7** from
Start. It runs alongside Windows PowerShell 5.1. Official instructions:
[PowerShell](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows),
[uv](https://docs.astral.sh/uv/getting-started/installation/).

## 2. Download this project and the original driver

In normal PowerShell 7, use a new destination:

```powershell
git clone https://github.com/japetrov/mc808-usb-win.git C:\MC808-Test
Set-Location C:\MC808-Test
```

Open [Roland's Windows 7 MC-808 driver page](https://www.roland.com/global/support/by_product/mc-808/updates_drivers/3aeb2115-e416-4baf-8455-539cade75826/).
Select **MC-808 Driver Version 1.0.0 for Windows 7 32-bit 64-bit**, review its
terms and download the ZIP yourself. Extract All using Explorer. Keep the ZIP
and extracted originals unchanged; do not choose Vista, XP or the system update.

Find its `Files\64bit\Files` folder. Adjust the example source path below to
match your extraction, including any extra top-level directory:

```powershell
$vendorFiles = 'C:\MC808-Vendor\Files\64bit\Files'
New-Item -ItemType Directory -Force .\Files\64bit\Files
Copy-Item -LiteralPath "$vendorFiles\RDWM1064.SYS", "$vendorFiles\RDIF1064.INF", "$vendorFiles\RDCI1064.DLL", "$vendorFiles\RDCP1064.CPL", "$vendorFiles\RDDP1064.DAT" -Destination .\Files\64bit\Files
Get-FileHash .\Files\64bit\Files\RDWM1064.SYS -Algorithm SHA256
```

The original SYS must be 81920 bytes, SHA256:
`984f00a9ffe11380e63392e7d7f6e3e5f70aa178a9764d47fc790a2170aaf084`.
If it differs, stop; never edit a fingerprint to bypass the check.

## 3. Prepare Python and patch the INF

From C:\MC808-Test in normal PowerShell 7:

```powershell
uv python install 3.12
uv venv --python 3.12 --seed .venv-analysis
.venv-analysis\Scripts\python.exe -m pip install -r requirements-analysis.txt
.venv-analysis\Scripts\python.exe tools\patch_inf.py Files\64bit\Files\RDIF1064.INF
```

If Python 3.12 is already available, `py -3.12 -m venv .venv-analysis` can
replace the first two commands. No environment activation is required.

The INF patcher writes **build\inf\RDIF1064.INF**, a `.diff` and hash record.
It updates OS/model decorations, lab DriverVer and catalog name, preserving
hardware ID and install/service/interface directives. It never overwrites the
source. Package preparation uses this same function automatically: **do not
copy the patched INF back over the original**. INF edits alone do not fix HVCI.

Accepted source INF SHA256 values:

- Legacy layout: `13c97f6b18807378effc924fed3945d51e6ac7ba4902c3615e628077987a1c28`
- Earlier research layout: `bb86216efd50efebbac52e238658b6de1887d97561f4bf02377102a499b5fdc4`

Unknown INF/companion revisions are rejected. Report hashes/version for review,
not the vendor file. Do not hand-edit until a hash check passes.

## 4. Patch the SYS and run checks

```powershell
.venv-analysis\Scripts\python.exe tools\analyze_pe.py Files\64bit\Files\RDWM1064.SYS --output reports\original-pe.json
.venv-analysis\Scripts\python.exe tools\setup_research_tools.py uasm
.venv-analysis\Scripts\python.exe tools\candidate_writer.py --experimental --accept-conditional-init --accept-unproven-nx-use
.venv-analysis\Scripts\python.exe tools\compare_candidate.py
.venv-analysis\Scripts\python.exe tools\prepare_test_package.py
.venv-analysis\Scripts\python.exe -m unittest discover -s tests -v
```

The flags acknowledge unresolved INIT/NX assumptions, not deployment approval.
The scripts rebuild page-aligned sections, fix metadata/references and add NX
allocation shims, preserving the original SYS. The result is
**build\experimental\RDWM1064.experimental.sys**, expected SHA256:
`4d2a21846897975e615d095b94cfb54d39ffb88d61380205e501bbff6d4504c6`.
The five-file unsigned package is build\test-package\driver.
**Do not install that unsigned package.** Optional signing-integration tests
may be skipped until signed artifacts exist; test failures are not expected.

## 5. Create and verify the test-signed package

Normal PowerShell 7, project root:

```powershell
.venv-analysis\Scripts\python.exe tools\setup_sdk_signing.py
.venv-analysis\Scripts\python.exe tools\setup_research_tools.py wdk
.\tools\create_test_signed_copy.ps1 -Package
```

Review SDK/WDK terms; the pinned WDK download is about 106 MiB. No system SDK
installer runs. If execution policy blocks the PowerShell script, inspect
`Get-ExecutionPolicy -List`. On a personally managed test machine with no
enforced policy, explicitly allowing local scripts **only in this session** is
an option; retry after this command:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
```

Do not override organization policy or use Bypass/Unrestricted as a general fix.
PowerShell script policy is separate from kernel-driver signing.

Signing prints a unique **build\test-signed-packages\TIMESTAMP-ID** folder.
Only a folder with manifest.json is complete. It contains `driver\` with the
signed SYS, patched INF, companions and fresh signed catalog. The public
certificate and checks sit outside `driver\`. The same new certificate signs
SYS and catalog; its transient private key is deleted. No system trust changes.

Select and check the latest completed run:

```powershell
$testPackage = (Get-ChildItem .\build\test-signed-packages -Directory |
    Where-Object { Test-Path (Join-Path $_.FullName 'manifest.json') } |
    Sort-Object Name | Select-Object -Last 1).FullName
$testPackage
.venv-analysis\Scripts\python.exe tools\verify_signed_package.py $testPackage
.\tools\verify_catalog_signature.ps1 -Catalog "$testPackage\driver\MC808_EXPERIMENTAL.CAT" -Certificate "$testPackage\MC808-Research-Test.cer"
Get-Content "$testPackage\manifest.json"
```

Both checks must succeed. Save the path and certificate thumbprint. Each run
has a different signed hash; the historical signed hash in STATUS.md will not
match your run. Do not modify the signed payload afterward.

## 6. Prepare recovery and back up the old driver — Administrator

Keep the MC-808 disconnected. Prepare backup/recovery and ensure this machine's
BitLocker recovery key is accessible from another device. Never share that key.
Open **Windows PowerShell as administrator** and inspect:

```powershell
Confirm-SecureBootUEFI
Get-BitLockerVolume -MountPoint C: | Select-Object MountPoint,VolumeStatus,ProtectionStatus
bcdedit.exe /enum "{current}"
reagentc.exe /info
pnputil.exe /enum-drivers /class Media
```

If the old MC-808 driver is present, find its **Published Name** beside Original
Name RDIF1064.INF / provider Roland. Do not assume oem8.inf or select a package
for another Roland device. Replace **oemNN.inf** with that actual name:

```powershell
New-Item -ItemType Directory -Force C:\MC808-Rollback
pnputil.exe /export-driver oemNN.inf C:\MC808-Rollback
```

Verify export and copy it externally. A driver-file export is not a system
backup. If no old MC-808 package is installed, skip its export/removal.

## 7. Configure Test Mode — Administrator

This self-signed test route changes boot/security configuration. Stop here if
you cannot accept that; no production-signed alternative is supplied. When
Secure Boot is enabled, it blocks the normal Test Mode route. If C: is encrypted
and protected, temporarily suspend BitLocker before firmware/boot changes:

```powershell
Suspend-BitLocker -MountPoint C: -RebootCount 2
```

The disk stays encrypted, but protection is temporarily suspended. Restart into
UEFI, disable **Secure Boot only**, and return to Windows. Do not clear keys,
clear the TPM or change storage-controller/boot mode. In administrator PowerShell:

```powershell
bcdedit.exe /set "{current}" testsigning on
```

Restart normally if successful. Do not substitute the one-boot "Disable driver
signature enforcement" startup option. Resume BitLocker if you suspended it:

```powershell
Resume-BitLocker -MountPoint C:
Confirm-SecureBootUEFI
bcdedit.exe /enum "{current}"
Get-BitLockerVolume -MountPoint C: | Select-Object MountPoint,VolumeStatus,ProtectionStatus
```

Expect Secure Boot False, testsigning Yes, and BitLocker protection On if used.
Extra restarts can exhaust the suspension count; keep recovery access available.
Stop on errors instead of adding other boot overrides. See
[Microsoft Test Mode requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option).

## 8. Remove the old blocker and enable Memory Integrity — Administrator

If you identified/backed up the old package, recheck its name and remove only it:

```powershell
pnputil.exe /delete-driver oemNN.inf /uninstall
```

Stop on failure; do not add `/force`. Open **Windows Security → Device security
→ Core isolation details**, turn on **Memory Integrity**, then restart normally.
Investigate any separately listed incompatible driver; do not delete unrelated
packages. After restarting, verify:

```powershell
Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard |
    Select-Object VirtualizationBasedSecurityStatus,SecurityServicesRunning
```

SecurityServicesRunning must contain **2**. VBS status 2 by itself is insufficient.

## 9. Trust your certificate and stage your package — Administrator

In the administrator terminal, return to the project and reselect the package;
variables do not carry over from earlier windows:

```powershell
Set-Location C:\MC808-Test
$testPackage = (Get-ChildItem .\build\test-signed-packages -Directory |
    Where-Object { Test-Path (Join-Path $_.FullName 'manifest.json') } |
    Sort-Object Name | Select-Object -Last 1).FullName
Get-Content "$testPackage\manifest.json"
certutil.exe -addstore Root "$testPackage\MC808-Research-Test.cer"
certutil.exe -addstore TrustedPublisher "$testPackage\MC808-Research-Test.cer"
pnputil.exe /add-driver "$testPackage\driver\RDIF1064.INF"
```

Run individually, stopping on failure. These commands deliberately change
machine trust and stage the driver; the Python tools do not. Trust only your
own certificate. Record the new Published Name; Windows can reuse an old oem
number. See [Microsoft certificate guidance](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/installing-test-certificates).

## 10. Connect and test — deliberate first driver load

Set the MC-808 USB Mode to **MIDI**, connect/power it on and wait for device
setup. Windows may invoke the original INF-declared co-installer even though
you did not run Setup.exe. In administrator PowerShell:

```powershell
Get-CimInstance Win32_PnPEntity |
    Where-Object { $_.PNPDeviceID -like 'USB\VID_0582&PID_00A9*' } |
    Select-Object Name,Status,ConfigManagerErrorCode,Service
Get-CimInstance Win32_SystemDriver -Filter "Name='RDID1064'" |
    Select-Object Name,State,PathName
Get-FileHash "$testPackage\driver\RDWM1064.SYS", "$env:SystemRoot\System32\drivers\rdwm1064.sys" -Algorithm SHA256
Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard |
    Select-Object VirtualizationBasedSecurityStatus,SecurityServicesRunning
```

Expect problem code 0, service Running, identical package/installed hashes, and
SecurityServicesRunning containing 2. These hashes identify the file on disk,
not the in-memory module. If a check fails, retain the error and relevant Code
Integrity/SetupAPI observations; do not turn HVCI off to claim an HVCI pass.

Open the MIDI application, select MC-808 input/output, and test safe data both
ways. Close/reopen and retry; record the app and workload. The closed-editor
sleep/resume case is known to fail; reconnect USB for the observed workaround.
Do not use firmware updates or overwrite personal patches as a driver test.

## Rollback — Administrator

Close MIDI apps and disconnect the device. Re-identify the **candidate's current**
published INF using its recorded name and lab version/date. Remove only that
package with `pnputil.exe /delete-driver oemNN.inf /uninstall`, replacing the name.
Remove only your experiment's certificate using the exact CertificateThumbprint
from its manifest.json (replace YOUR_TEST_CERT_THUMBPRINT below):

```powershell
certutil.exe -delstore Root YOUR_TEST_CERT_THUMBPRINT
certutil.exe -delstore TrustedPublisher YOUR_TEST_CERT_THUMBPRINT
bcdedit.exe /set "{current}" testsigning off
```

Restart as needed and restore your original Secure Boot configuration, handling
BitLocker suspension/resumption as above if changing firmware. Confirm BitLocker
protection is On. The original Roland driver needs its known-working Memory
Integrity-off configuration; reinstalling it is not an HVCI-preserving fallback.
Review that choice before restoring the exported vendor package. If Windows
cannot boot, use the prepared recovery method; do not blindly delete SYS files
or assume offline Windows drive letters match the running system.

Never upload generated drivers, vendor files, catalogs, certificates, private or
recovery keys, disassembly or private logs to GitHub. Share hashes and minimal
redacted observations. The next development step is paired USB resume tracing.
