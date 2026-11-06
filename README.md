# Roland MC-808 Windows 11 driver research

Experimental tools to analyze and reconstruct the original MC-808 Windows 7
x64 driver for investigation with Windows 11 Memory Integrity (HVCI).
Unofficial research; not affiliated with or endorsed by Roland.

**Current result:** bidirectional transfers worked on one Windows 11 25H2
machine in Test Mode, with HVCI confirmed running and the installed SYS hash
matching the reconstructed candidate. Secure Boot was off. This is not a
production-signed driver or a generally qualified Windows 11 release.

**Known issue:** closing MC-808 Editor before sleep causes communication to fail
after wake/reopen. Leaving the editor open across sleep worked in the reported
test. USB reconnect restored communication after failure. These are observed
workarounds, not a fix. See [test status](docs/STATUS.md).

## Contents

- Python PE analysis, reconstruction, comparison and fragment-emulation tools.
- Newly written shim assembly, pinned tool descriptions and offline signing.
- Automated tests and source-only GitHub Actions checks.
- Build, manual testing and contribution documentation.

**No driver binaries, vendor DLLs, catalogs, certificates, private keys or
installer are distributed.** Obtain the original package from
[Roland support](https://www.roland.com/global/support/by_product/mc-808/) and
review its terms. The tools accept one exact x64 input hash.

## Start here

1. Read [RIGHTS.md](RIGHTS.md). The bundled Roland notice restricts modification
   and redistribution. This project currently has **no open-source license**.
   A tooling repository does not resolve rights to modify or redistribute
   Roland software or vendor-derived material.
2. Follow the [step-by-step download, patch and test tutorial](docs/TUTORIAL.md).
   The shorter [build reference](docs/BUILD.md) is also available.
3. Review [manual testing](docs/TESTING.md) before considering a hardware load.
4. See [CONTRIBUTING.md](CONTRIBUTING.md) for reproducible reports.

## Layout

| Path | Purpose |
| --- | --- |
| tools/ | Analysis, reconstruction, verification and offline signing |
| tests/ | Full suite requires separately obtained vendor input |
| asm/reconstruction/ | Newly written NX allocation shims |
| toolchains/ | Portable assembler pins |
| docs/ | Portable build, test, publishing and status guides |
| Files/, .tools/, build/, reports/*.json | Local-only inputs and artifacts |

The full research checkout additionally retains historical reports and reviewed
vendor disassembly. Those and the research Git history are excluded from the
separate clean publishing repository.

## Limits

The original SYS is hash-bound and never patched in place. Candidate creation
requires three experimental acknowledgments. Reconstruction accounts for
references and PE metadata rather than merely changing section alignment.
pefile/LIEF comparisons and Unicorn fragment checks do not prove every runtime
path, INIT alias safety or NX-buffer lifetime property.

Offline signing tools generate temporary test certificates. They never import
trust, change boot/security settings, install or load drivers. Manual testing
is separate. A self-signature does not establish retail Windows kernel trust.

## Publishing

Run tools/prepare_github_repository.py to prepare the curated snapshot under
ignored build/github-ready/. It excludes research history, reviewed vendor
disassembly, machine-specific reports and generated payloads. It never pushes.
See [publishing](docs/PUBLISHING.md). Rights review remains open; use a private
GitHub repository initially, rather than presenting this as a redistributable
driver release.
