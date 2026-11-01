# 0001: Go single binary with embedded Caddy

- **Status:** Accepted
- **Date:** 2026-11-01

## Decision

RyProx is written in Go and ships as a single binary. Caddy is embedded as a library to do the actual proxying and automatic HTTPS. The web UI is compiled and embedded in the same binary. SQLite is the default database.

## Why

- **Go** is memory-safe, fast, very good at network code, and produces one static binary that is easy to install.
- **Caddy** already does automatic HTTPS and accepts its full config as JSON through an API, swapping it live with no downtime. If a new config is invalid it is rejected and the old one keeps running. This is exactly the "UI-first, live reload" behaviour RyProx needs.
- **One binary** means users install one thing; no separate proxy, database or web server to manage.
- **SQLite** needs no setup. Postgres comes later for multi-node.

## Rejected alternatives

- **Writing our own proxy from scratch:** far more work and risk (HTTP/2, HTTP/3, TLS, ACME). Possible later for special cases.
- **Traefik:** good, but its dynamic config model is less suited to embedding and live JSON swaps.
- **Rust:** excellent for safety, but slower to build with for a solo developer, and Caddy's ecosystem is in Go.
