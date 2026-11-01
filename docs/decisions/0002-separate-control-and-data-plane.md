# 0002: Separate control plane and data plane from day one

- **Status:** Accepted
- **Date:** 2026-11-01

## Decision

The code is split into a **control plane** (UI, API, database) and a **data plane** (the proxy that handles traffic), even while both run in one binary.

- The data plane receives config only through an internal, authenticated API. It never reads the database directly.
- The data plane keeps its last good config on disk and keeps running from it if the control plane is unreachable.

## Why

Multi-node (Milestone 7) then becomes "run the data plane on another machine", not a rewrite. It also limits damage: a bug in the proxy can't touch the database, and the admin UI being down doesn't take sites offline.

## Consequences

Slightly more code early on (an internal API instead of direct function calls). Worth it.
