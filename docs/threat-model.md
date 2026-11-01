# Threat model

A living document, reviewed at the end of every milestone. Last reviewed: M0, 2026-11-01.

## What we protect

1. **Users' private services** behind RyProx (NAS, cameras, admin panels).
2. **The admin account and UI**, which control everything.
3. **Secrets:** TLS private keys, DNS API tokens, CrowdSec keys, tunnel keys, session tokens.
4. **User identities and sessions** for protected routes.

## Who might attack

| Attacker | Goal |
| --- | --- |
| Internet scanners and bots | Find exposed services, brute-force logins |
| Targeted attacker | Bypass auth to reach a specific private service |
| Malicious logged-in user | Reach routes they aren't allowed, escalate to admin |
| Compromised site agent | Move from one site into others or into the control plane |
| Supply-chain attacker | Ship malicious code via a dependency or our release process |

## Key risks and planned defences

| Risk | Defence | Milestone |
| --- | --- | --- |
| Auth bypass via path tricks (`..`, `%2F`, `//`) | Normalise paths once; routing and auth use the same normalised path; test suite of known tricks | M2, M4 |
| Admin login brute force | Argon2id hashing, rate limiting, lockout, mandatory TOTP for admins | M1 |
| Setup wizard takeover on a fresh install | Wizard disabled permanently once the first admin exists; listens on localhost until set up | M1 |
| Spoofed `X-Forwarded-*` / identity headers | Strip all incoming identity headers; only trust forwarded headers from configured proxies; sign identity headers | M1, M4 |
| Session theft / cookie reuse across domains | Host-bound, short-lived, HttpOnly, Secure, SameSite cookies | M1, M4 |
| Open redirects | Redirect targets restricted to same-host paths unless an admin sets a full URL | M2 |
| Slowloris / resource exhaustion | Server timeouts and header size limits (done in M0), rate limits, CrowdSec | M0, M3 |
| Secrets leaking in logs | Secrets encrypted at rest; structured logging with redaction | M1 |
| Compromised agent reaches other sites | Per-site keys and allow-lists; agents can't reach the control plane database | M5 |
| Malicious dependency | Minimal dependencies, pinned versions, govulncheck in CI, signed releases | M0 onward |

## Done in M0

- HTTP server timeouts and a 64 KiB header limit
- Default listen address is localhost only
- `/healthz` reveals no version or system information
- CI with least-privilege permissions, govulncheck and gosec
