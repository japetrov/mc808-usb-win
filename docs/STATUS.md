# Test status — 2026-11-06

One experimental build was manually tested on one machine. These results do
not establish compatibility with every Windows build, USB controller or workload.

| Check | Result |
| --- | --- |
| Last OS baseline | Windows 11 25H2 build 26200.9711 |
| Test configuration | Test Mode, Secure Boot off, HVCI confirmed running |
| Initial bidirectional transfer | Passed |
| Application close/reopen, ordinary USB reconnect | Passed |
| Sleep with editor closed, reopen after wake | Failed: unable to read/write |
| Sleep with editor left open | Worked in the reported sequence |
| USB reconnect following failed resume | Restores communication |
| Sustained traffic, timing/loss, broad SysEx, restart | Not qualified |
| Other machines, production signing / normal retail policy | Not qualified |

After failed resume, HVCI and the driver service remained running, with device
problem code 0. This does not prove functional MIDI requests. A limited recent
Code Integrity search found no Roland-related message.

## Identities

Original SYS SHA256:
`984f00a9ffe11380e63392e7d7f6e3e5f70aa178a9764d47fc790a2170aaf084`

Deterministic unsigned candidate SHA256:
`4d2a21846897975e615d095b94cfb54d39ffb88d61380205e501bbff6d4504c6`

Historical signed candidate installed-file SHA256:
`dfe783f33b09ec8431cc14b8a7ef99ea7edeb38c5e26c690d98eddd40c1000a4`

New signing runs create a different certificate and signed hash. No signing
certificate or driver binary is supplied to other users.

## Open work

Compare USB traces of closed/open-editor resume and audit MIDI port lifecycle,
pending requests and power transitions. Resolve INIT indirect aliases and full
NX buffer-use/lifetime conditions, broaden qualification and review modern INF
requirements. Licensing and supported production distribution remain unresolved.
The resume failure has not been compared with the unmodified driver in a
controlled test. Do not treat the observed workarounds as a patch specification.
