# Changelog

All notable changes to RyProx are recorded here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Zero-trust access (brought forward from Milestone 4).
  - Routes are private by default; public is an explicit per-route choice. Missing or unknown access settings are treated as private.
  - Every request to a private site is checked: a session for that exact site, an enabled account, and a place on the site's access list. Revocation and disabling take effect on the next request.
  - Built-in sign-in portal at `/.ryprox/` on private sites (password + authenticator), with safe return to the requested page.
  - People: invite links (single-use, 7 days, token kept out of URLs sent to servers), member and admin roles, disable, remove. At least one admin always remains; admins can't lock themselves out.
  - Members can't use the dashboard. Sessions are bound to one site; cookies are stripped before forwarding; a trustworthy `X-RyProx-User` header is passed to apps and forged copies removed.
  - Passwords are never accepted over plain HTTP from other machines. User IDs are never reused, and removed users are taken off every access list.
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
  - Quick-install script (`install.sh`): asks the essentials, checks ports, DNS and firewall, installs with Docker or as a system service, pre-configures HTTPS, prints the setup code, and updates existing installs.
  - `ryprox init` to pre-configure HTTPS and the dashboard domain.
  - Release workflow: binaries for Linux (amd64, arm64, armv7) and macOS with checksums, and multi-arch Docker images on ghcr.io.
- Project skeleton: licence, README, security note, CI.
