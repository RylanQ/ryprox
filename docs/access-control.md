# Access control

Every route is either private or public. New routes are private.

- **Private**: visitors must sign in, and only people on the route's access list are let through. RyProx checks each request, so removing someone from the list or disabling their account takes effect on their next request.
- **Public**: anyone can open the route. Use this only for content meant to be public, or for applications that handle their own authentication.

## Signing in

A visitor without a valid session is redirected to RyProx's sign-in page at `/.ryprox/login` on the same domain. Requests that aren't page loads, such as API calls and WebSocket connections, receive `401` instead. Signing in requires the account password and an authenticator code (or a recovery code). Afterwards the visitor is returned to the page they originally requested.

Visitors who are signed in but not on the access list are shown a *No access* page.

Sessions are bound to the domain they were created on. Signing in to one route does not grant a session on any other route or on the dashboard.

Passwords are only accepted over HTTPS, or from the server itself. Private routes therefore need [HTTPS](https.md) enabled before people can sign in from other devices.

The `/.ryprox/` path is reserved on private routes and is never forwarded to the service. On public routes it is forwarded like any other path.

## Users

| Role | Permissions |
| --- | --- |
| Member | Open the private routes they have been added to. |
| Admin | Same as member, plus use the dashboard. |

Users are managed under **People**:

- **Invite someone** creates a single-use link, valid for seven days, for a new user with a chosen role and routes. The recipient sets their own password and authenticator. The link is shown only once.
- **Disable** signs the user out everywhere and blocks sign-in; the account is kept.
- **Remove** deletes the account and takes the user off every access list.

You cannot change your own role, disable or remove yourself, or remove the last admin.

Invite links use the dashboard domain if one is set, otherwise the domain of a private route. Without HTTPS, they only work from the server itself.

## Identity header

Requests forwarded on private routes include `X-RyProx-User` with the signed-in username. Any value sent by the visitor is removed first, so applications can rely on it. All `X-RyProx-*` headers from visitors are removed on every route.

RyProx's session cookies are stripped from forwarded requests, so services never receive them.

## Account security

| Mechanism | Details |
| --- | --- |
| Passwords | At least 12 characters, stored as Argon2id hashes. |
| Two-factor authentication | TOTP, required for every account. Each code is accepted once. |
| Recovery codes | Ten single-use codes per account. Admins can generate new ones under **Settings**. |
| Rate limiting | Five failed attempts are allowed. Each further failure locks sign-in for 30 seconds, doubling each time up to one hour. Limits apply per account and per IP address. |
| Sessions | Expire after 12 hours of inactivity or 7 days. Admins can see and end their sessions under **Settings → Signed-in devices**. Changing a password ends all other sessions. |
| Dashboard | Strict content security policy, CSRF protection and clickjacking protection. |
| Activity | Sign-ins, refused sign-ins and changes are recorded under **Activity** with the client address. |

## Limitations

- Scripts and API clients cannot sign in. A route used by non-browser clients must be public, and should rely on the application's own authentication.
- Signing in to several private routes requires signing in to each one separately.
