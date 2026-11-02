# Changelog

Notable changes to RyProx are documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

Initial release.

### Added

- Reverse proxy with host-based routing, round-robin and failover load balancing, active and passive health checks, WebSockets and header rules.
- Web dashboard for routes, users, certificates and settings. Changes apply without a restart.
- Automatic HTTPS via ACME, with Let's Encrypt staging support and custom certificate authorities.
- Access control: routes are private by default, with per-route access lists, a sign-in page, member and admin roles, and invite links.
- Password and TOTP authentication with recovery codes, rate limiting, session management and an activity log.
- `X-RyProx-User` header identifying the signed-in user to backend services.
- Install script, Docker image, Docker Compose file and systemd unit.
- `init`, `reset-admin`, `healthcheck` and `version` commands.
