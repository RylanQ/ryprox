# Routes

A route forwards requests for one domain to one or more backend services. Routes are created and edited under **Routes** in the dashboard and take effect as soon as they are saved. If a change would leave the configuration invalid, it is rejected and the running configuration is kept.

## Fields

| Field | Description |
| --- | --- |
| Domain name | The hostname to serve, e.g. `photos.example.com`. Wildcards are not supported yet. |
| Route is on | Turning a route off stops serving it without deleting it. |
| Who can open this site? | Private (default) or public. See [access control](access-control.md). |
| Services | Backend addresses, e.g. `http://192.168.1.10:2342`. Use **Test** to check that RyProx can reach one. Up to 20 per route. |

## Multiple services

With more than one service, choose how requests are distributed:

- **Spread requests across all services**: round-robin.
- **Use the first service; switch only if it's down**: failover, in the order listed.

A service is skipped while it is marked down. If every service is down, RyProx still tries one rather than refusing the request.

## Health checks

When enabled, RyProx requests a path on each service (default `/`) at a fixed interval (default 15 seconds, between 5 and 3600). A service is marked down if the request fails or returns a 5xx status, and up again once a check succeeds.

Independently of health checks, a service that refuses a connection is skipped for 10 seconds.

The colour of the line on the routes page shows the state:

| Colour | State |
| --- | --- |
| Green | All services healthy |
| Amber | Some services down |
| Red | All services down |
| Grey | Health checks disabled |
| Dashed | Route turned off |

## Options

| Option | Default | Description |
| --- | --- | --- |
| Redirect HTTP to HTTPS | On | Redirect `http://` requests with a 308. Has no effect while HTTPS is off. |
| Allow WebSockets | On | Allow connection upgrades. Many applications need this for live updates. |
| Pass the original domain to the service | Off | Send the visitor's `Host` header instead of the service's address. Some applications need this to build links. |
| Accept the service's self-signed certificate | Off | Skip certificate verification for `https://` services. Use only on networks you trust. |

## Header rules

Header rules set or remove headers on requests sent to the service, or on responses sent to visitors. Up to 50 rules each. Headers that control the connection itself, such as `Host`, `Connection` and `Transfer-Encoding`, cannot be changed.

## Forwarded headers

Requests to services include `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto` and `X-Real-IP`, describing the visitor. Any values the visitor sent for these headers are discarded first. Private routes also receive [`X-RyProx-User`](access-control.md#identity-header).

## Error pages

| Status | Cause |
| --- | --- |
| 404 | No enabled route matches the domain. |
| 502 | The service did not respond. The page does not reveal the service's address. |
| 403 | The request was a WebSocket upgrade and WebSockets are disabled for the route. |
