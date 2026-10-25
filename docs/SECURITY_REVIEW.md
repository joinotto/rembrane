# Independent security review package

Run the review from a clean, committed worktree:

```sh
node scripts/generate-security-review-manifest.mjs > security-review-manifest.json
```

The generated manifest records the exact Git revision and SHA-256 digest of
each tracked security-sensitive source file, protocol artifact, migration,
workflow, threat model, and dependency lock. Reviewers should sign or otherwise
attest to the exact manifest they examined; a branch name or moving tag is not
sufficient evidence.

The generator refuses a dirty worktree by default. `--allow-dirty` exists only
for deterministic local and CI validation and must not be used for review
evidence.

An independent report should include:

- reviewer identity and independence statement;
- review dates, methodology, and explicit exclusions;
- the manifest SHA-256 and source revision;
- findings with severity, affected paths, and reproduction evidence;
- remediation commits or documented accepted-risk decisions; and
- a final disposition for authentication, tenant isolation, encryption and
  key handling, protocol boundaries, provider trust, deletion, backup, and
  recovery.

Do not commit confidential vulnerability details before coordinated
remediation. Follow `SECURITY.md` for private reporting.
