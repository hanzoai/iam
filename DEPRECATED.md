# DEPRECATED — this working copy is the pre-cutover Casdoor fork

The code in this directory is dead. It is not what builds, not what deploys, and
not what `github.com/hanzoai/iam` publishes. Do not read it to learn how IAM
behaves, and do not import it.

**Canonical: the clean-room v2 tree — checked out at `../iam2`, and served by
`origin/main` of this same repo.**

## What actually happened

`github.com/hanzoai/iam` (the GitHub repo, and the Go module path) is alive and
canonical. It was **cut over** from the Casdoor fork to a clean-room v2
implementation. This local checkout never followed the cutover: it is parked on
a pre-cutover branch, 357 commits behind `origin/main`.

So one module path shows two different codebases depending on where you look:

| Where | Content |
| --- | --- |
| `origin/main` of this repo | clean-room v2 — `internal/`, `server/`, `pkg/`, `feature/` |
| the published module in the Go module cache | clean-room v2 — same layout |
| the running service | clean-room v2 |
| **this working tree** | **Casdoor fork — `object/`, `controllers/`, `conf/`** |

`../iam2` is a checkout of the same canonical v2 line through a mirror remote
(`hanzoai/iam2`). Its `module github.com/hanzoai/iam` line is correct: it names
the repo that really publishes that path. The two share history — iam2's tip sits
directly beneath this repo's `origin/main`.

## Why this tree is actively misleading

It is not merely stale. It contains plausible, well-commented implementations of
things that were re-implemented from scratch in v2, so reading it yields
confident, wrong answers. The worked example is the RFC 8628 device grant:

- dead, here: `controllers/token.go` → `handleDeviceCodeToken`
- live: `internal/oidc/device.go` in the v2 tree

Both look complete. Only the second one runs. The same trap applies to the OIDC
authorize path, token issuance, and the user/lockout model.

Confirming which tree is live takes one grep — pick a string from a production
response and search both. For example `"authorization error: "` exists only in
the v2 tree, at `internal/oidc/authorize.go`.

## What to do instead

Read `../iam2`, or bring this checkout current:

    git -C . fetch origin && git -C . checkout origin/main

This file only exists on the pre-cutover line, so once this checkout is current
it disappears on its own.

## Do not clobber this checkout

It is not disposable. It holds **239 local commits that are not on any remote**,
plus uncommitted changes, on branch `feat/sqlite-hanzo-driver`. Whoever owns that
work has to land or abandon it deliberately. Nothing here should be reset,
force-updated, or deleted on someone else's behalf.

## Open item

Two remotes publish this one line — `hanzoai/iam` (canonical) and `hanzoai/iam2`
(mirror). One module path should have one repo. Retiring the `iam2` mirror, once
the cutover is acknowledged, is what actually closes this out.
