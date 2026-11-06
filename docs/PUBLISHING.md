# Clean publishing repository

Use the curated repository, not the full research history, for later GitHub
upload. RIGHTS.md is unresolved: prepare a private remote initially. No binary
release or public redistribution permission is implied by this preparation.

From the research checkout, run:

```powershell
python tools\prepare_github_repository.py
```

This writes an allowlisted source snapshot at build/github-ready/ and a separate
hash manifest beside it. It excludes vendor inputs, reviewed/generated vendor
disassembly, raw reports, local signing/rollback artifacts and .git history.
It refuses differing existing files or unexpected export contents. It never
clears a directory or copies the parent .git. To refresh an initialized snapshot,
review and commit the intended source changes there manually; the exporter is
not a synchronization or history-rewriting tool.

The prepared snapshot is initialized with a separate main branch and clean
history. The parent research repository remains intact and has no remote. Do
not push from the parent repository accidentally. In the clean repository:

```powershell
python -m unittest discover -s tests -p test_publication.py -v
python -m compileall -q tools tests
python tools\audit_repository.py --history
git status --short
git ls-files
git remote -v
```

The audit checks tracked files and optionally historical blobs for excluded
paths/types, binary content, private-key markers and machine-specific user paths.
It is not a comprehensive secret scanner, legal clearance or driver safety test.
It intentionally rejects the full research checkout's historical reports.
The GitHub workflow repeats these source-only checks without vendor inputs,
toolchain downloads, signing, certificate imports or driver loading.

When the user supplies an empty remote and chooses its visibility, attach that
remote to this clean repository and push main. No remote is configured and no
push takes place during preparation. Recheck the audit after every content or
history change; do not attach local build outputs to releases/issues.
