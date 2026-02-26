AI Action Firewall Client v1 (Hard-Fail Gate)

What it does (PHASE 5):
- Diff-only (added lines)
- Canonical intent (schema=intent-v1, policy_id=ai-secrets-v1)
- POST to Authority /admit
- Verify:
  - pinned pubkey_sha256 via /pubkey
  - ed25519 signature over canonical record bytes
- Fail-closed: any mismatch => exit 1

This repo is a composite GitHub Action (no Docker).