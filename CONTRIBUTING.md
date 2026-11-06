# Contributing

Read RIGHTS.md first. Licensing/public redistribution remain unresolved.

Reports should include Windows build, controller/USB port type, HVCI runtime
state, signing mode, unsigned/signed hashes and exact reproduction. For resume,
state whether MIDI applications were open before sleep and whether reconnect
recovers communication. Remove usernames, serials and unrelated log content.

Do not upload vendor files, disassembly, catalogs, certificates, private/recovery
keys or personal MIDI/SysEx dumps. Supply minimal relevant observations and
hashes instead. Keep full logs local and redact any extracts before sharing.

Changes must preserve original input, explain every binary modification and
keep conditional assumptions explicit. Run relevant static/emulation tests;
never add automatic installation, driver loading, trust imports or boot/security
changes to build/test tools. GitHub Actions never loads a kernel driver.

See docs/BUILD.md for full tests and docs/PUBLISHING.md for source-only checks.
No contributor license agreement or automatic relicensing is implied here.
