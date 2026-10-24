# Production testing

Run the complete release-candidate gate with:

```sh
REMBRANE_POSTGRES_URL=postgresql://... \
  ./scripts/check-production-readiness.sh --strict
```

Strict mode requires dependency resolution, Rust and Postman tests, a live
PostgreSQL database dedicated to the destructive RLS fixture, and a working
Docker daemon. It fails rather than silently skipping unavailable gates.

`available` mode runs every usable gate and reports missing infrastructure. It
is suitable during offline development but is not production approval.

Independent security review, platform credentials, external-provider
conformance, and real WhatsApp/Apple integration accounts remain human or
external-system release gates and cannot be self-certified by this script.
