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
  security-review-manifest.json review-bundle \
  security-review-attestation.json
```

Consumers verify the manifest, attestation, checksums, their exact linkage, and
both signatures with the reviewer's independently trusted public key:

```sh
sh scripts/verify-security-review-bundle.sh \
  review-bundle reviewer-public.pem
```

Omitting the optional attestation argument produces only a signed inventory.
That proves integrity but must not be represented as reviewer approval.

The generator refuses a dirty worktree by default. `--allow-dirty` exists only
for deterministic local and CI validation and must not be used for review
evidence. The signer also rejects dirty manifests, permissive or symbolic
private keys, ambiguous or control-bearing paths, and any pre-existing output
directory. It signs only a private copied manifest that passes validation
again after transfer. Before signing, the verifier also requires the manifest
revision, complete tracked-file inventory, byte lengths, and SHA-256 digests
to match the current clean checkout exactly.

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

`spec/security-review-attestation.schema.json` defines the content-free public
attestation record. It binds reviewer independence, the exact manifest digest
and revision, scope exclusions, aggregate finding counts, and final
disposition without requiring confidential finding details in the repository.
Validate it with:

```sh
node scripts/verify-security-review-attestation.mjs review-attestation.json
```

An `approved` disposition requires no exclusions or unresolved findings.
`approved_with_accepted_risks` still requires zero unresolved findings, a
bounded `reportReference`, and at least one non-informational finding or
explicit scope exclusion. Accepted-risk rationale and owner-approved treatment
belong in the referenced private or coordinated report.
`changes_required` requires at least one unresolved finding.
