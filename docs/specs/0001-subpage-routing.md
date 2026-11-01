# 0001: Sub-page routing

- **Milestone:** M2
- **Status:** Draft
- **Date:** 2026-11-01

## Problem

Users want a domain to lead to a specific page of an app, or to send different paths of one domain to different services, without editing config files. This is not offered by comparable tools' UIs today.

## How it works in the UI

Three options on the route form:

| Option | Example | Field |
| --- | --- | --- |
| Landing page | Visiting `test.com` sends you to `test.com/page1` | "Default landing path" |
| Path-based routing | `test.com/page1` → service A, `test.com/app` → service B | "Add path rule" list |
| Backend base path | `test.com` serves `backend:8080/page1`; visitor never sees `/page1` | "Backend base path" |

A live preview under the form shows: *"A request to `test.com/page1/x` will go to `10.0.0.5:8080/x`."*

## Behaviour

- **Landing page:** only a request for exactly `/` is redirected. Status code selectable: 301 (permanent) or 302 (temporary, default). Query string preserved.
- **Path rules:** exact, prefix and wildcard matches. Most specific match wins, then the user's drag-and-drop order. Optional "strip prefix" per rule (`/app/x` → backend receives `/x`).
- **Backend base path:** the base path is prepended to every request path before forwarding.
- Overlapping rules show a warning before saving.

## Security considerations

- Normalise paths **before** matching: decode once, resolve `.` and `..`, collapse `//`. Reject encoded slashes (`%2F`) and encoded dots in path segments by default. This stops `test.com/public/..%2Fadmin` slipping past a rule for `/admin`.
- Path-based **auth rules must match on the same normalised path** the router uses, so access control and routing can never disagree.
- Landing redirect targets must be a path on the same host (start with a single `/`). Never an external URL: no open redirects (`//evil.com`, `/\evil.com`).
- Strip-prefix must never produce an empty path; it becomes `/`.

## Tests

- Each of the three options, including preview text matching real behaviour
- Traversal attempts: `/a/../admin`, `/a/%2e%2e/admin`, `/a/..%2Fadmin`, `//admin`, `/admin/`, mixed case
- Open-redirect attempts in the landing path field
- Priority ordering and overlap warnings

## Origin of the idea

Requested by the project founder from their own use. Path-based routing and redirects are standard, documented reverse-proxy behaviour (e.g. Caddy's public docs).
