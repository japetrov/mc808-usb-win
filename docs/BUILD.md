# Local analysis and build

Read ../RIGHTS.md first. These are local research steps, not a driver release
license. Windows x64 and Python 3.12 are the documented native-build environment.
Run commands from the repository root; no administrator rights are needed for
analysis/reconstruction. Tools never install or load the resulting driver.

## Inputs

Obtain your own MC-808 Windows 7 x64 package from
[Roland support](https://www.roland.com/global/support/by_product/mc-808/).
Place its original SYS at Files/64bit/Files/RDWM1064.SYS. Required size: 81920;
SHA256: `984f00a9ffe11380e63392e7d7f6e3e5f70aa178a9764d47fc790a2170aaf084`.
Never modify it. Other revisions/x86 drivers are rejected, not silently adapted.

## Environment and deterministic unsigned candidate

```powershell
py -3.12 -m venv .venv-analysis
.venv-analysis\Scripts\python.exe -m pip install -r requirements-analysis.txt
.venv-analysis\Scripts\python.exe tools\analyze_pe.py Files\64bit\Files\RDWM1064.SYS --output reports\original-pe.json
.venv-analysis\Scripts\python.exe tools\setup_research_tools.py uasm
.venv-analysis\Scripts\python.exe tools\candidate_writer.py --experimental --accept-conditional-init --accept-unproven-nx-use
.venv-analysis\Scripts\python.exe tools\compare_candidate.py
```

UASM is downloaded to ignored .tools/ and hash-checked; no system installation
or PowerShell policy change is needed. Check its bundled license. The candidate
writer verifies the native shim bytes and performs fresh pefile/LIEF comparisons.
The flags acknowledge unresolved INIT RX and NX-use assumptions; they do not
approve deployment. See STATUS.md for unsigned/signed hash distinctions.

Outputs are build/experimental/RDWM1064.experimental.sys and manifest, comparison
and research sidecars. Expected unsigned SHA256:
`4d2a21846897975e615d095b94cfb54d39ffb88d61380205e501bbff6d4504c6`.
The writer refuses to overwrite a different candidate or the original input.

## Full offline tests

The generated original report and candidate above are prerequisites. Tests also
require the hash-bound INF and companion files below, because package tests are
part of the suite. Native UASM checks use the pinned local executable.

```powershell
.venv-analysis\Scripts\python.exe -m unittest discover -s tests -v
```

Signing integration tests run only when completed signed artifacts exist; an
unsigned fresh build skips those optional cases. No test loads a kernel driver.
On GitHub Actions only source/publication checks run, without Roland inputs.

## Optional local package and test signature

Place your separately obtained RDCI1064.DLL, RDCP1064.CPL, RDDP1064.DAT and
reviewed RDIF1064.INF beside the original SYS. The preparer accepts only the exact
fingerprints listed in tools/prepare_test_package.py. The current INF pin is the
research checkout's previously modified INF, not a promise that every original
download has identical bytes. If your INF differs, package preparation stops:
it needs explicit review/adaptation before this optional route can be used.
Do not fake a fingerprint or modify the original to satisfy the check.
The SYS-only reconstruction above does not depend on the INF.

```powershell
.venv-analysis\Scripts\python.exe tools\prepare_test_package.py
.venv-analysis\Scripts\python.exe tools\setup_sdk_signing.py
.venv-analysis\Scripts\python.exe tools\setup_research_tools.py wdk
pwsh -NoProfile -File tools\create_test_signed_copy.ps1 -Package
```

Review Microsoft SDK/WDK terms before downloading; the WDK package is about
106 MiB. No tool installer is run. PowerShell 7 is required for signing; if policy
blocks the script, review that separately rather than bypassing it automatically.
The signing command requires SignTool's valid publisher signature and pinned
hash. It creates a restricted, unique build/test-signed-packages folder, signs
the SYS, creates a fresh 25H2 catalog, and signs it with the same ephemeral key.
It verifies SYS cryptography/preservation, catalog cryptography and all five
memberships before marking completion. The transient PFX is deleted. Nothing
is imported into certificate stores or installed. Each run has a new certificate
and signed hash. Do not trust or distribute someone else's research certificate.

The lab INF retains legacy co-installer and directory behavior, with known
modern WHQL submission failures. Successful Inf2Cat generation does not override
those failures, establish retail trust or prove reliable resume.
