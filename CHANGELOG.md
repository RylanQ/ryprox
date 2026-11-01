# Changelog

All notable changes to RyProx are recorded here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Milestone 1: core proxy and admin dashboard.
  - Routes managed entirely from the dashboard, applied live with no restart; invalid changes are never saved.
  - Multiple services per route with round-robin or failover, health checks, and passive failure detection.
  - WebSockets, header rules, optional original-Host passthrough, optional self-signed backend support.
  - Automatic HTTPS with Let's Encrypt (production or test certificates), HTTP→HTTPS redirects, certificate status page, optional HTTPS admin domain, and support for a custom ACME server.
  - First-run setup protected by a one-time code from the logs; two-step sign-in with an authenticator app; single-use recovery codes.
  - Argon2id passwords, encrypted authenticator secrets, replay protection, login lockout, session management, CSRF protection, strict security headers.
  - Activity log of every sign-in and change.
  - `ryprox reset-admin` to recover a locked-out install; `ryprox healthcheck` for Docker.
  - Dockerfile (distroless, non-root), Docker Compose file and hardened systemd service.
  - User guide in `docs/GUIDE.md`.
- Project skeleton: licence, README, security note, CI.
