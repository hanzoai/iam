# Security Policy

## Reporting a vulnerability

Email security@hanzo.ai with details. Encrypt with our PGP key (fingerprint TBD).

We respond within 48 hours. Critical issues receive same-day acknowledgment.

## Scope

This policy covers code in this repository. For the broader Hanzo platform threat model, see [hanzoai/HIPs](https://github.com/hanzoai/HIPs).

## Sandbox boundary

`iam` is the identity provider trusted by every other Hanzo subsystem; a compromise of its signing key invalidates all platform JWTs and is treated as a top-severity incident. Tenants are isolated by organization namespace, all credentials are stored hashed (bcrypt / argon2), and JWT signing keys are rotated by KMS.

For runtime sandbox guarantees, see HIP-0105 (in-process extension runtimes).
