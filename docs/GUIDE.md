# RyProx guide

RyProx sends visitors from your domains (like `photos.example.com`) to services running on your network (like `http://192.168.1.10:2342`), with free HTTPS certificates and a login-protected dashboard. Everything is set from the dashboard; there are no config files to edit.

**Contents**

1. [What you need](#1-what-you-need)
2. [Install](#2-install)
3. [First-time setup](#3-first-time-setup)
4. [Open the dashboard safely](#4-open-the-dashboard-safely)
5. [Add your first route](#5-add-your-first-route)
6. [Who can open your sites (zero trust)](#6-who-can-open-your-sites-zero-trust)
7. [Turn on HTTPS](#7-turn-on-https)
8. [Route options explained](#8-route-options-explained)
9. [Your account and security](#9-your-account-and-security)
10. [Backups, updates and recovery](#10-backups-updates-and-recovery)
11. [Troubleshooting](#11-troubleshooting)
12. [Real-world test checklist](#12-real-world-test-checklist)
13. [How RyProx works](#13-how-ryprox-works)

---

## 1. What you need

- **A server** that the internet can reach: a cheap VPS (Hetzner, DigitalOcean, etc.) or a machine at home with ports forwarded. Linux, macOS and Windows all work; these instructions assume Linux.
- **Ports 80 and 443 open** to the internet on that server. Let's Encrypt uses them to check you own the domain.
- **A domain name.** For each site, create a DNS **A record** pointing at the server's public IP address. For example:

  | Name | Type | Value |
  | --- | --- | --- |
  | `photos.example.com` | A | `203.0.113.10` |
  | `ryprox.example.com` | A | `203.0.113.10` |

  If you use Cloudflare, set these records to **DNS only** (grey cloud) while you start out.

- **An authenticator app** on your phone: Google Authenticator, 1Password, Aegis, Bitwarden, or similar.

## 2. Install

### Quick install (recommended)

On your server, run:

```sh
curl -fsSL https://raw.githubusercontent.com/RylanQ/ryprox/main/install.sh | sudo bash
```

It asks a few questions (dashboard domain, email for HTTPS, test or real certificates), checks that ports 80/443 are free and your DNS points at the server, opens the firewall if you want, installs RyProx with Docker or as a system service, and prints your setup code.

Prefer to read a script before running it as root? Good habit:

```sh
curl -fsSLO https://raw.githubusercontent.com/RylanQ/ryprox/main/install.sh
less install.sh
sudo bash install.sh
```

Run the same command again later to **update**; your routes and settings are kept.

For automation, every answer can be given as an option, e.g.
`sudo bash install.sh --docker --domain ryprox.example.com --email me@example.com --staging --yes`.
Add `--dry-run` to see what it would do without changing anything.

Or install by hand with one of the options below.

### Option A: Docker Compose

```sh
git clone https://github.com/RylanQ/ryprox.git
cd ryprox
docker compose -f deploy/docker-compose.yml up -d --build
docker compose -f deploy/docker-compose.yml logs ryprox
```

The container runs as a non-root user, with a read-only filesystem and no extra privileges. Everything RyProx stores lives in the `ryprox-data` volume.

### Option B: Binary with systemd

Download a release from the [releases page](https://github.com/RylanQ/ryprox/releases), or build it (needs Go 1.26 or newer):

```sh
git clone https://github.com/RylanQ/ryprox.git
cd ryprox
make build
sudo useradd --system --home-dir /var/lib/ryprox --shell /usr/sbin/nologin ryprox
sudo cp bin/ryprox /usr/local/bin/
sudo cp deploy/ryprox.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ryprox
sudo journalctl -u ryprox
```

The service file locks RyProx down: it runs as the unprivileged `ryprox` user, which can only bind ports 80/443 and write to `/var/lib/ryprox`.

### Option C: Just run it (for trying out)

```sh
make build
./bin/ryprox serve --http :8080 --https :8443 --data ./data
```

### Command-line options

You rarely need these; everything else is set in the dashboard. Each also works as an environment variable.

| Option | Environment variable | Default | What it does |
| --- | --- | --- | --- |
| `--data` | `RYPROX_DATA` | `./data` | Where the database, secret key and certificates are stored |
| `--http` | `RYPROX_HTTP` | `:80` | Public HTTP address |
| `--https` | `RYPROX_HTTPS` | `:443` | Public HTTPS address |
| `--admin` | `RYPROX_ADMIN` | `127.0.0.1:8081` | Dashboard address. Keep it on `127.0.0.1` |
| `--log-level` | `RYPROX_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error` |
| `--log-format` | `RYPROX_LOG_FORMAT` | `text` | `text` or `json` |
| `--acme-directory` | `RYPROX_ACME_DIRECTORY` | Let's Encrypt | Advanced: use your own certificate authority (e.g. step-ca) |
| `--acme-ca` | `RYPROX_ACME_CA` | | Advanced: root certificate file for that authority |

## 3. First-time setup

When RyProx starts for the first time, it prints a **setup code** in its logs:

```
────────────────────────────────────────────────────────────
  RyProx dev is running
  Admin dashboard: http://127.0.0.1:8081

  First-time setup code:  AD4B-HHAX-9F2J
  Enter it in the dashboard to create your admin account.
────────────────────────────────────────────────────────────
```

The code makes sure only someone who can see the server's logs can create the admin account. It works once, and a new one is printed each restart until setup is done.

1. Open the dashboard (see the next section).
2. Enter the setup code, choose a username and a password of at least 12 characters.
3. Scan the QR code with your authenticator app and type in the 6-digit code it shows.
4. **Save your 10 recovery codes** somewhere safe, like a password manager. Each one lets you sign in once if you lose your phone.

## 4. Open the dashboard safely

The dashboard only listens on the server itself (`127.0.0.1:8081`), so nobody on the internet can reach it. You have two ways in.

**SSH tunnel (works straight away).** On your own computer, run:

```sh
ssh -L 8081:127.0.0.1:8081 you@your-server
```

Leave that window open and visit **http://localhost:8081**. The connection is encrypted by SSH.

**Its own domain (once HTTPS is on).** Under **Settings → HTTPS**, fill in *Admin dashboard domain* (e.g. `ryprox.example.com`). RyProx gets a certificate for it and serves the dashboard there, over HTTPS only. You still need your password and authenticator code to sign in.

## 5. Add your first route

A **route** connects a domain to one or more services.

1. Go to **Routes → Add route**.
2. **Domain name**: e.g. `photos.example.com`. Just the name, no `https://` and no path.
3. **Services**: the address you'd use on your own network, e.g. `http://192.168.1.10:2342`. Click **Test** to check RyProx can reach it.
4. **Who can open this site?** New routes are **private**: only the people you tick can open them, after signing in. You're ticked to start with. See the next section.
5. Click **Add route**. It's live immediately; there's nothing to restart.

The routes page shows each route as a wire from the domain to its services:

| Wire | Meaning |
| --- | --- |
| Teal | All services healthy |
| Amber | Some services are down |
| Red | All services are down |
| Grey | Health checks are off, so RyProx doesn't know |
| Dashed | The route is switched off |

Hover over a service to see its response time or the last error.

## 6. Who can open your sites (zero trust)

RyProx follows **zero trust**: nobody is trusted because of where they connect from, and every request is checked. In practice:

- **Every new route is private.** Only people you choose can open it. Making a site public is a deliberate choice you make per route.
- **Every request is checked**, not just the first: the person's session, that their account is still enabled, and that they're still on the site's list. If you take someone off a site or disable them, their very next click is refused.
- **Each site has its own sign-in.** Signing in to `photos.example.com` doesn't open `nas.example.com` or the dashboard. A stolen cookie from one site is useless on the others.
- **Two steps, always**: password plus authenticator code, for everyone.
- **Passwords are never accepted over plain HTTP** (except on the server itself). Private sites need automatic HTTPS for people to sign in from other devices.

### What visitors see

Someone opening a private site without being signed in gets a RyProx sign-in page (at `/.ryprox/login` on that site). After signing in they land on the page they asked for. If they're signed in but not on the list, they see a *No access* page.

The `/.ryprox/` path is reserved by RyProx on private sites; it never reaches your app. On public sites it's passed through untouched.

### Adding people

1. Go to **People → Invite someone**.
2. Enter a username, choose **Member** or **Admin**, and tick the sites they may open.
3. Click **Create invite link** and send them the link. It works once, expires after 7 days, and is only shown to you once.
4. They open it, choose their own password and set up their authenticator app. You never see either.

| Role | Can do |
| --- | --- |
| **Member** | Open the private sites they've been given. Nothing else. |
| **Admin** | Everything a member can, plus manage RyProx in the dashboard. |

From the People page you can change someone's role, **Disable** them (signed out everywhere instantly, account kept), or **Remove** them (taken off every site too). You can't disable or remove yourself, and RyProx always keeps at least one admin.

Invite links use your dashboard domain if you've set one, otherwise the address of one of your private sites. Until HTTPS is on, they only work from the server itself.

### What your apps receive

For private sites, RyProx tells your app who is signed in with an `X-RyProx-User` header. RyProx removes any copy of this header sent by a visitor, so apps can trust it. RyProx also removes its own sign-in cookie before forwarding, so a compromised app can never steal someone's RyProx session.

### Public sites

Choose **Anyone on the internet** only for things meant to be public (a blog, a status page). Make sure the app has its own login if it needs one.

## 7. Turn on HTTPS

1. Make sure each domain's DNS points at your server, and ports 80 and 443 are open.
2. Go to **Settings → HTTPS** and choose **Automatic HTTPS**.
3. Enter your email (Let's Encrypt only uses it for expiry warnings).
4. **Start with *Use test certificates* turned on.** Browsers will show a warning, but you can't hit Let's Encrypt's rate limits while you get DNS and ports right.
5. Save, then open **Certificates**. Each domain should change from *Getting certificate* to *Test certificate* within a minute.
6. Once everything works, turn **Use test certificates off** and save. Real certificates arrive within a minute.

Certificates renew automatically about 30 days before they expire. Visitors to `http://` addresses are redirected to `https://` (you can turn this off per route).

**Choose *HTTP only*** if another proxy in front of RyProx already handles HTTPS, or for testing on a home network.

## 8. Route options explained

- **Route is on**: switch a route off to stop serving it without deleting it. The toggle on the routes page does the same.
- **More than one service**: *Spread requests* sends visitors to each service in turn (load balancing). *Use the first service* only uses the others if the first is down (failover).
- **Redirect HTTP to HTTPS**: on by default. Only matters when HTTPS is on.
- **Allow WebSockets**: needed by many apps for live updates (Home Assistant, chat apps, dashboards). On by default.
- **Pass the original domain to the service**: turn on if the app needs to know which domain it was opened on. Some apps (Nextcloud, WordPress) need this.
- **Accept the service's self-signed certificate**: for `https://` services on your own network that use self-signed certificates (Proxmox, some NAS boxes). Only use it inside a network you trust.
- **Health check**: RyProx requests a page (e.g. `/` or `/health`) every few seconds. A service that fails or answers with a 5xx error stops receiving visitors until it recovers. Even without health checks, a service that refuses connections is skipped for 10 seconds.
- **Header rules** (advanced): add or remove HTTP headers on requests to your service or on responses to visitors. For example, remove the `Server` header, or set `X-Frame-Options: DENY`.

Every service receives `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host` and `X-Real-IP` with the visitor's real details. RyProx removes any of these headers the visitor sends, so they can't be faked.

## 9. Your account and security

What RyProx does to keep you safe:

- **Two-step sign-in**: password plus an authenticator code on every login. A code can't be used twice.
- **Slow-down on guessing**: after 5 wrong passwords or codes, each further attempt is locked out for longer (30 s, 1 min, 2 min… up to an hour).
- **Passwords** are stored with Argon2id. **Authenticator secrets** are encrypted with a key kept in a separate file (`secret.key`).
- **Sessions** end after 12 hours of inactivity or 7 days at most. Under **Settings → Signed-in devices** you can see every device and sign it out.
- **Changing your password** signs out every other device.
- The dashboard blocks cross-site request forgery and clickjacking, and only runs its own scripts.
- **Activity** lists every sign-in and change, with the address it came from.

If you lose your phone, sign in with a recovery code, then make new codes under **Settings → Recovery codes**.

## 10. Backups, updates and recovery

**Back up the data folder** (`ryprox-data` volume, or `/var/lib/ryprox`). It holds:

| File | What it is |
| --- | --- |
| `ryprox.db` | Routes, settings, account, activity log |
| `secret.key` | Encrypts your authenticator secret. **Keep it with the database**; neither works without the other |
| `certs/` | Certificates (RyProx can always get new ones) |

**Updating**: run the quick-install command again. If you installed by hand, pull the new version and rebuild (`docker compose ... up -d --build`, or `make build` and restart the service). The database upgrades itself.

**Someone else locked out?** An admin can remove them on the People page and send a new invite.

**Locked out completely** (lost phone *and* recovery codes, and no other admin)? On the server, run:

```sh
ryprox reset-admin --yes            # or: docker compose ... run --rm ryprox reset-admin --yes
```

then restart RyProx. Routes, settings and members are kept; a new setup code is printed so you can create an admin account again. (You'll need to tick yourself on your private routes again.)

## 11. Troubleshooting

| Problem | Likely cause and fix |
| --- | --- |
| *Certificate failed* | DNS doesn't point at this server yet (check with `dig photos.example.com`), or port 80/443 is blocked by a firewall or your router. Fix it, then click **Try again** on the Certificates page. |
| Browser warns about the certificate | You're still on test certificates. Turn them off in Settings. |
| *Service unavailable* (502) page | RyProx can't reach the service. Use **Test** in the route editor. Check the address and port, and that the service accepts connections from the RyProx server (in Docker, `localhost` means the container itself: use the host's LAN IP instead). |
| *Not found* (404) page | No route matches that domain, or the route is switched off. |
| *No access* page | You're signed in, but not on that site's list. An admin can tick you in the route's *Who can open this site?* section. |
| "Signing in needs HTTPS" | Private sites only accept passwords over HTTPS. Turn on automatic HTTPS in Settings. |
| An app or API client gets *401 Sign-in needed* | The route is private. Scripts and API clients can't sign in yet; make that route public if it has its own authentication. |
| App loads but redirects in a loop or breaks | Turn on *Pass the original domain to the service*, and set the app's own "external URL" setting to `https://your-domain`. |
| Live updates don't work | Make sure *Allow WebSockets* is on. |
| "Too many attempts" | Wait for the time shown; the lockout lifts automatically. |
| Where's the setup code? | In the logs: `docker compose ... logs ryprox` or `journalctl -u ryprox`. |
| `bind: permission denied` on port 80/443 | Running outside Docker/systemd without permission. Use the systemd service, or `sudo setcap cap_net_bind_service=+ep /usr/local/bin/ryprox`. |

## 12. Real-world test checklist

Work through this on a real server and domain. Tick as you go.

**Install and setup**
- [ ] The quick-install script asks its questions, warns about anything wrong (DNS, busy ports), and finishes with a setup code
- [ ] RyProx starts and prints a setup code
- [ ] Dashboard opens through the SSH tunnel at `http://localhost:8081`
- [ ] A wrong setup code is refused
- [ ] Setup with password + authenticator works; recovery codes download
- [ ] Restarting RyProx doesn't print a new setup code

**Routes over HTTP**
- [ ] A new route is private by default, with you ticked
- [ ] Add a route to a real service; **Test** says *Reachable*
- [ ] `http://your-domain` shows the service
- [ ] An unknown domain pointed at the server shows *Not found*
- [ ] Switching the route off makes it show *Not found*; switching on brings it back instantly

**HTTPS**
- [ ] Automatic HTTPS with test certificates: certificate appears within a minute
- [ ] Switch to real certificates: browser shows a padlock with no warning
- [ ] `http://` redirects to `https://`
- [ ] Admin dashboard domain works over HTTPS, and `http://` to it redirects

**Behaviour**
- [ ] An app using WebSockets (e.g. Home Assistant) works live
- [ ] Two services + health check: stop one, its wire turns amber, visitors still get the other
- [ ] Stop all services: wire turns red, visitors see the *Service unavailable* page

**Zero trust** (needs HTTPS on)
- [ ] Opening a private site in a private/incognito window shows the RyProx sign-in page
- [ ] After signing in you land on the page you originally asked for
- [ ] Invite a second person (or yourself on another device) with access to one site; they can set up their account and open it
- [ ] Their sign-in doesn't open your other sites or the dashboard
- [ ] Untick them on the route: their next page load says *No access*
- [ ] Disable them on the People page: they're signed out at once
- [ ] A public route opens without any sign-in

**Security**
- [ ] Five wrong passwords, then a lockout message
- [ ] The same authenticator code can't be used twice
- [ ] A recovery code signs you in once, not twice
- [ ] Changing the password signs out your other devices
- [ ] Activity shows all of the above

Please note anything that's confusing or broken: that's the most useful feedback.

## 13. How RyProx works

This section is for the curious, and for anyone working on the code.

```
             internet
                │
   ┌────────────┼──────────────┐
   │ :80        │ :443         │       :8081 (127.0.0.1 only)
   ▼            ▼              │            ▼
 HTTP         HTTPS            │      Admin dashboard ──► JSON API
 listener     listener ◄── certificates      │               │
   │            │              (Let's Encrypt)│               ▼
   └─────┬──────┘                             │          SQLite database
         ▼                                    │               │
   Proxy engine  ◄──── live configuration ────┴───────────────┘
         │
         ▼
   your services (192.168.1.10:2342, …)
```

- **One program.** RyProx is a single Go binary with the dashboard built in. There is no separate web server, proxy or database to install.
- **The database is the source of truth.** When you save a route, RyProx validates it, saves it inside a transaction, checks the *whole* configuration still builds, and only then commits. If anything is wrong, nothing is saved and the old configuration keeps running.
- **Live changes, no restarts.** The proxy engine holds an immutable snapshot of all routes. A change builds a new snapshot and swaps it in atomically: requests already in flight finish on the old one, new requests use the new one. Nothing is dropped.
- **Control plane and data plane are separate.** The dashboard and API (control plane) never handle visitors' traffic; the proxy engine (data plane) never touches the database. This is what will let RyProx run several proxy nodes from one dashboard in a later version.
- **The access gate.** For private routes, the proxy engine asks the gate before forwarding anything: is there a session cookie, is it for *this* site, is it unexpired, is the account enabled, is the person on the site's list? Any "no" stops the request at RyProx. The sign-in portal under `/.ryprox/` is served by RyProx itself.
- **Certificates** come from Let's Encrypt using the ACME protocol, via Go's `autocert` package. RyProx only allows certificates for domains you've configured, so a stranger pointing a random domain at your server can't make it request certificates.

**Code layout**

| Folder | What's in it |
| --- | --- |
| `cmd/ryprox` | The command-line program: `serve`, `init`, `reset-admin`, `healthcheck`, `version` |
| `install.sh` | The quick-install script |
| `internal/server` | Starts everything and wires the listeners together |
| `internal/proxy` | The proxy engine: routing, load balancing, health checks |
| `internal/certs` | Automatic HTTPS |
| `internal/api` | The dashboard's JSON API, login, sessions and security headers |
| `internal/auth` | Passwords, authenticator codes, recovery codes, rate limiting |
| `internal/config` | Checks everything you type before it's saved |
| `internal/store` | The SQLite database |
| `internal/secrets` | Encrypts sensitive values at rest |
| `internal/web/static` | The dashboard's HTML, CSS and JavaScript |

Run the tests with `make test`. They include attack cases: forged headers, Host-header tricks, replayed codes, cross-site requests, password guessing, sessions reused across sites, revoked and disabled users, and members trying to reach the dashboard.
