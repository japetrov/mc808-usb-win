# Manual testing

Read STATUS.md and ../RIGHTS.md. Resume with the editor closed is known to fail.
No automatic install/load test or vendor installer is provided. The local lab
INF still registers the original co-installer DLL; Windows may invoke it during
device operations. It has not been deleted merely to satisfy modern INF rules.

Use a recoverable test machine, preserve its working package and prepare rollback.
Keep recovery credentials accessible from another device; never share them.
Record build, Secure Boot, encryption, Test Mode and HVCI state before changes.
Do not automatically change execution policy if a PowerShell script is blocked.

Offline signing is artifact preparation only. A self-signed SYS/catalog does not
satisfy normal retail policy. Review Microsoft's separate
[test signing/HVCI requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option)
and [test certificate trust](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/installing-test-certificates).
No build command imports certificates or changes security settings.

After a deliberately chosen manual installation, verify installed SYS hash,
bound package/service and actual HVCI running state. Staging alone is not proof
of loading. Preserve relevant Code Integrity and SetupAPI observations locally.

Test safe bidirectional MIDI, application reopen and ordinary USB reconnect.
Compare closed-versus-open application sleep/resume and record recovery
separately. Only after basic stability, test sustained traffic and safe SysEx
with counts/durations. Do not overwrite patches or update firmware as a test.

The read-only tools/collect_test_state.ps1 records local observations; some
queries require administrator privileges. Failures remain Unknown. It collects
no BitLocker recovery keys and never changes drivers, policy or trust.
Stop on hangs, corrupted transfers or crashes; keep evidence before recovery.
