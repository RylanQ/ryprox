# Architecture

RyProx is a single Go binary. The dashboard is embedded and the database is SQLite, so there are no external dependencies at run time.

```
           :80 / :443                          127.0.0.1:8081
               │                                     │
        ┌──────▼───────┐                     ┌───────▼────────┐
        │ proxy engine │◄── configuration ───│ dashboard, API │
        │  access gate │                     └───────┬────────┘
        └──────┬───────┘                             │
               │                              ┌──────▼──────┐
               ▼                              │   SQLite    │
           services                           └─────────────┘
```

## Configuration

The database is the source of truth. A change made in the dashboard is written inside a transaction; before the transaction commits, the complete set of routes is validated and compiled into a proxy configuration. If either step fails, the transaction is rolled back and the error is returned to the dashboard.

The compiled configuration is an immutable snapshot. Applying a change swaps the snapshot atomically: requests in flight complete on the old snapshot and new requests use the new one.

The proxy engine never reads the database, and the dashboard never handles proxied traffic. Keeping the two separate is intended to allow proxy nodes to run on other machines later.

## Request handling

For each request the engine:

1. Looks up the route by the `Host` header (case-insensitive, port removed). Unknown hosts get a 404.
2. Removes `X-RyProx-*` headers sent by the client.
3. For private routes, asks the access gate to authorize the request. The gate checks for a session cookie, that the session belongs to this host and hasn't expired, that the account is enabled, and that the user is on the route's access list. Requests under `/.ryprox/` are handled by the sign-in portal instead.
4. Removes RyProx cookies, sets `X-Forwarded-*`, `X-Real-IP` and `X-RyProx-User`, applies header rules, and forwards the request to a backend chosen by the route's load-balancing policy.

## Sessions

Session tokens are 256-bit random values. Only their SHA-256 hashes are stored. Each session records the host it was issued for; an empty host denotes the dashboard. Dashboard sessions additionally require the admin role at the time of each request.

Authenticator secrets are encrypted with AES-256-GCM using the key in `secret.key`.

## Code layout

| Package | Responsibility |
| --- | --- |
| `cmd/ryprox` | Command-line interface |
| `internal/server` | Startup and listeners |
| `internal/proxy` | Routing, load balancing, health checks, access gate interface |
| `internal/api` | Dashboard API, sign-in, sessions, sign-in portal, users |
| `internal/auth` | Password hashing, TOTP, recovery codes, rate limiting |
| `internal/certs` | ACME certificate management |
| `internal/config` | Input validation |
| `internal/store` | SQLite storage and migrations |
| `internal/secrets` | Encryption of values at rest |
| `internal/web/static` | Dashboard and sign-in portal front end |

## Tests

`make test` runs all tests with the race detector. Beyond unit tests, the suite covers forged forwarding and identity headers, host header variations, replayed TOTP codes, cross-site requests, brute-force limits, sessions presented on the wrong host, revoked and disabled users, and database migrations from earlier schema versions.
