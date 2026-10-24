# Rembrane Recovery Model

**Status:** Pre-alpha local deployment baseline

This document defines what Rembrane backs up, how recovery is verified, and
which failures cannot be repaired. It is a safety contract, not a promise that
pre-alpha builds are suitable for production data.

## Recovery assets

A recoverable local deployment requires two independently protected assets:

1. the encrypted SQLite backup produced by `rembrane backup`; and
2. the exact workspace key material referenced by
   `REMBRANE_WORKSPACE_KEY_ID`, retained independently in the configured key
   provider.

The database contains ciphertext, non-secret routing metadata, canonical event
history, evidence references, checkpoints, disclosure receipts, membership
records, deletion tombstones, and pending provider-projection work. The
workspace key is intentionally not embedded in the database or backup. In an
OS keyring profile, recovery therefore requires restoring or synchronizing the
corresponding macOS Keychain or Linux Secret Service item; the SQLite backup
alone is insufficient.

## Backup

`rembrane backup`:

- authenticates the configured principal, workspace membership, and every
  readable encrypted memory before backup;
- uses SQLite `VACUUM INTO` to create a transactionally consistent standalone
  database;
- refuses to overwrite an existing destination; and
- preserves encrypted records without decrypting them into an export file.

Backups should be copied to storage with independent access controls and
retention. Keeping the backup beside the live database does not protect
against device loss.

## Restore

`rembrane restore`:

- restores only into a new destination;
- validates the database schema version;
- verifies the configured principal has active workspace membership;
- authenticates encrypted memory, event, and checkpoint records with the
  supplied workspace key; and
- removes the newly created destination if verification fails.

Backups use the single-file `rembrane-encrypted-export-v1` framing format.
The payload is a consistent SQLite snapshot whose sensitive canonical fields
remain record-encrypted. Restore rejects unknown versions, truncated payloads,
trailing bytes, overwrites, and records that cannot be authenticated with the
configured workspace key.

After restore, run `rembrane doctor` and a representative `rembrane recall`
before reconnecting agents. Provider indexes are derived state; deployments
must replay or rebuild projections when a provider is introduced.

## Failure cases

### Database lost, key available

Recover from the newest valid encrypted backup. Events after that snapshot are
lost unless another synchronized replica contains them.

### Key lost, database available

Strict-E2EE content is unrecoverable. Maintainers and infrastructure providers
must not have a hidden recovery key. Development environment variables are not
a production recovery mechanism. Losing the OS keyring item and every
separately protected recovery copy has the same irreversible result.
Windows DPAPI CurrentUser blobs are bound to the Windows user and machine
protection context; copying the blob alone to another host or account is not a
recovery strategy.

### Database available, wrong key

AEAD authentication fails closed. Rembrane does not return partial plaintext
or silently try another workspace.

### Rolled-back backup

The restored database is internally consistent but may predate corrections,
deletions, membership changes, or disclosure receipts. Before stable release,
sync cursors and signed or externally anchored recovery epochs are required to
detect rollback across devices.

### Removed shared-workspace member

The pre-alpha CLI and authenticated REST API can orchestrate a required
group-key rotation through a configured customer-controlled HTTP key provider.
They derive the exact recipient set from canonical active membership and
persist only the correlated content-free provider receipt. Deployments still
cannot claim forward secrecy unless their provider actually replaces the
workspace key and prevents removed members from using future generations.

## Required operator drill

Before relying on a deployment:

1. create disposable memory;
2. create an encrypted backup;
3. restore it to a different path;
4. run `rembrane doctor`;
5. recall the disposable memory;
6. prove a wrong key fails and leaves no destination; and
7. securely remove the disposable drill data.

The repository CLI end-to-end test automates this drill for the local adapter.
