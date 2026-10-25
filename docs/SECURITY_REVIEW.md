# Independent security review package

Run the review from a clean, committed worktree:

```sh
node scripts/generate-security-review-manifest.mjs > security-review-manifest.json
```

The generated manifest records the exact Git revision and SHA-256 digest of
every tracked regular file. The full-repository inventory deliberately avoids
subjective security-sensitive filters that could omit application entry
points, review tooling, deployment files, or indirect dependencies. Reviewers
should sign or otherwise attest to the exact manifest they examined; a branch
name or moving tag is not sufficient evidence.

For detached Ed25519 attestation, keep the reviewer private key outside the
repository, restrict it to owner-only mode (`0400` or `0600`), and run:

```sh
REMBRANE_SECURITY_REVIEW_SIGNING_KEY=/protected/reviewer-private.pem \
  sh scripts/sign-security-review-manifest.sh \
  security-review-manifest.json review-attestation
```

Consumers verify the exact manifest bytes with the reviewer's independently
trusted public key:

```sh
sh scripts/verify-security-review-signature.sh \
  review-attestation/security-review-manifest.json \
  review-attestation/security-review-manifest.json.sig \
  reviewer-public.pem
```

The generator refuses a dirty worktree by default. `--allow-dirty` exists only
for deterministic local and CI validation and must not be used for review
evidence. The signer also rejects dirty manifests, permissive or symbolic
private keys, ambiguous or control-bearing paths, symbolic output directories,
and existing artifact names.

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
