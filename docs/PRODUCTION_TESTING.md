# Production testing

Run the complete release-candidate gate with:

```sh
REMBRANE_POSTGRES_URL=postgresql://... \
REMBRANE_SECURITY_REVIEW_BUNDLE=/secure/review-bundle \
REMBRANE_SECURITY_REVIEW_PUBLIC_KEY=/secure/reviewer-public.pem \
REMBRANE_CUSTOMER_KMS_EVIDENCE_DIRECTORY=/secure/kms-provider-evidence \
REMBRANE_MEMORY_PROVIDER_EVIDENCE_DIRECTORY=/secure/memory-provider-evidence \
  ./scripts/check-production-readiness.sh --strict
```

Strict mode requires dependency resolution, Rust and Postman tests, a live
PostgreSQL database dedicated to the destructive RLS fixture, and a working
Docker daemon. The HTTP suites require permission to bind an ephemeral
loopback socket. It also verifies the independently signed security-review
bundle and exact AWS/Azure/GCP customer-KMS evidence set. It fails rather than
silently skipping unavailable gates. It also requires the exact
Memory Provider release-evidence directory containing two independent passing
providers, at least one externally maintained provider, and mixed-version
compatibility evidence. Both the independent review and provider evidence must
name the exact clean repository `HEAD`; evidence for an older or dirty source
tree is rejected.

`available` mode runs every usable gate and reports missing infrastructure. It
probes loopback binding before starting transport tests, so restricted
sandboxes report that suite as unavailable instead of failing midway. It is
suitable during offline development but is not production approval.

Platform credentials and real WhatsApp/Apple integration accounts remain
human or external-system release gates and cannot be self-certified by this
script. The script can verify retained security-review and customer-KMS
evidence and validate Memory Provider release evidence, but it cannot create
that independent evidence itself.
