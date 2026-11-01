# RyProx guide

RyProx sends visitors from your domains (like `photos.example.com`) to services running on your network (like `http://192.168.1.10:2342`), with free HTTPS certificates and a login-protected dashboard. Everything is set from the dashboard; there are no config files to edit.

**Contents**

1. [What you need](#1-what-you-need)
2. [Install](#2-install)
3. [First-time setup](#3-first-time-setup)
4. [Open the dashboard safely](#4-open-the-dashboard-safely)
5. [Add your first route](#5-add-your-first-route)
6. [Turn on HTTPS](#6-turn-on-https)
7. [Route options explained](#7-route-options-explained)
8. [Your account and security](#8-your-account-and-security)
9. [Backups, updates and recovery](#9-backups-updates-and-recovery)
10. [Troubleshooting](#10-troubleshooting)
11. [Real-world test checklist](#11-real-world-test-checklist)
12. [How RyProx works](#12-how-ryprox-works)

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

Pick one of these.

### Option A: Docker Compose (recommended)

```sh
git clone https://github.com/RylanQ/ryprox.git
cd ryprox
docker compose -f deploy/docker-compose.yml up -d --build
docker compose -f deploy/docker-compose.yml logs ryprox
```

The container runs as a non-root user, with a read-only filesystem and no extra privileges. Everything RyProx stores lives in the `ryprox-data` volume.

### Option B: Binary with systemd

Build it (needs Go 1.26 or newer):

```sh
git clone https://github.com/RylanQ/ryprox.git
cd ryprox
make build
sudo cp bin/ryprox /usr/local/bin/
sudo cp deploy/ryprox.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ryprox
sudo journalctl -u ryprox
```

The service file locks RyProx down: it runs as a throwaway user that can only bind ports 80/443 and write to `/var/lib/ryprox`.

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
4. Click **Add route**. It's live immediately; there's nothing to restart.

The routes page shows each route as a wire from the domain to its services:

| Wire | Meaning |
| --- | --- |
| Teal | All services healthy |
| Amber | Some services are down |
| Red | All services are down |
| Grey | Health checks are off, so RyProx doesn't know |
| Dashed | The route is switched off |

Hover over a service to see its response time or the last error.

## 6. Turn on HTTPS

1. Make sure each domain's DNS points at your server, and ports 80 and 443 are open.
2. Go to **Settings → HTTPS** and choose **Automatic HTTPS**.
3. Enter your email (Let's Encrypt only uses it for expiry warnings).
4. **Start with *Use test certificates* turned on.** Browsers will show a warning, but you can't hit Let's Encrypt's rate limits while you get DNS and ports right.
5. Save, then open **Certificates**. Each domain should change from *Getting certificate* to *Test certificate* within a minute.
6. Once everything works, turn **Use test certificates off** and save. Real certificates arrive within a minute.

Certificates renew automatically about 30 days before they expire. Visitors to `http://` addresses are redirected to `https://` (you can turn this off per route).

**Choose *HTTP only*** if another proxy in front of RyProx already handles HTTPS, or for testing on a home network.

## 7. Route options explained

- **Route is on**: switch a route off to stop serving it without deleting it. The toggle on the routes page does the same.
- **More than one service**: *Spread requests* sends visitors to each service in turn (load balancing). *Use the first service* only uses the others if the first is down (failover).
- **Redirect HTTP to HTTPS**: on by default. Only matters when HTTPS is on.
- **Allow WebSockets**: needed by many apps for live updates (Home Assistant, chat apps, dashboards). On by default.
- **Pass the original domain to the service**: turn on if the app needs to know which domain it was opened on. Some apps (Nextcloud, WordPress) need this.
- **Accept the service's self-signed certificate**: for `https://` services on your own network that use self-signed certificates (Proxmox, some NAS boxes). Only use it inside a network you trust.
- **Health check**: RyProx requests a page (e.g. `/` or `/health`) every few seconds. A service that fails or answers with a 5xx error stops receiving visitors until it recovers. Even without health checks, a service that refuses connections is skipped for 10 seconds.
- **Header rules** (advanced): add or remove HTTP headers on requests to your service or on responses to visitors. For example, remove the `Server` header, or set `X-Frame-Options: DENY`.

Every service receives `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host` and `X-Real-IP` with the visitor's real details. RyProx removes any of these headers the visitor sends, so they can't be faked.

## 8. Your account and security

What RyProx does to keep you safe:

- **Two-step sign-in**: password plus an authenticator code on every login. A code can't be used twice.
- **Slow-down on guessing**: after 5 wrong passwords or codes, each further attempt is locked out for longer (30 s, 1 min, 2 min… up to an hour).
- **Passwords** are stored with Argon2id. **Authenticator secrets** are encrypted with a key kept in a separate file (`secret.key`).
- **Sessions** end after 12 hours of inactivity or 7 days at most. Under **Settings → Signed-in devices** you can see every device and sign it out.
- **Changing your password** signs out every other device.
- The dashboard blocks cross-site request forgery and clickjacking, and only runs its own scripts.
- **Activity** lists every sign-in and change, with the address it came from.

If you lose your phone, sign in with a recovery code, then make new codes under **Settings → Recovery codes**.

## 9. Backups, updates and recovery

**Back up the data folder** (`ryprox-data` volume, or `/var/lib/ryprox`). It holds:

| File | What it is |
| --- | --- |
| `ryprox.db` | Routes, settings, account, activity log |
| `secret.key` | Encrypts your authenticator secret. **Keep it with the database**; neither works without the other |
| `certs/` | Certificates (RyProx can always get new ones) |

**Updating**: pull the new version and rebuild (`docker compose ... up -d --build`, or `make build` and restart the service). The database upgrades itself.

**Locked out completely** (lost phone *and* recovery codes)? On the server, run:

```sh
ryprox reset-admin --yes            # or: docker compose ... run --rm ryprox reset-admin --yes
```

then restart RyProx. Your routes and settings are kept; a new setup code is printed so you can create the account again.

## 10. Troubleshooting

| Problem | Likely cause and fix |
| --- | --- |
| *Certificate failed* | DNS doesn't point at this server yet (check with `dig photos.example.com`), or port 80/443 is blocked by a firewall or your router. Fix it, then click **Try again** on the Certificates page. |
| Browser warns about the certificate | You're still on test certificates. Turn them off in Settings. |
| *Service unavailable* (502) page | RyProx can't reach the service. Use **Test** in the route editor. Check the address and port, and that the service accepts connections from the RyProx server (in Docker, `localhost` means the container itself: use the host's LAN IP instead). |
| *Not found* (404) page | No route matches that domain, or the route is switched off. |
| App loads but redirects in a loop or breaks | Turn on *Pass the original domain to the service*, and set the app's own "external URL" setting to `https://your-domain`. |
| Live updates don't work | Make sure *Allow WebSockets* is on. |
| "Too many attempts" | Wait for the time shown; the lockout lifts automatically. |
| Where's the setup code? | In the logs: `docker compose ... logs ryprox` or `journalctl -u ryprox`. |
| `bind: permission denied` on port 80/443 | Running outside Docker/systemd without permission. Use the systemd service, or `sudo setcap cap_net_bind_service=+ep /usr/local/bin/ryprox`. |

## 11. Real-world test checklist

Work through this on a real server and domain. Tick as you go.

**Install and setup**
- [ ] RyProx starts and prints a setup code
- [ ] Dashboard opens through the SSH tunnel at `http://localhost:8081`
- [ ] A wrong setup code is refused
- [ ] Setup with password + authenticator works; recovery codes download
- [ ] Restarting RyProx doesn't print a new setup code

**Routes over HTTP**
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

**Security**
- [ ] Five wrong passwords, then a lockout message
- [ ] The same authenticator code can't be used twice
- [ ] A recovery code signs you in once, not twice
- [ ] Changing the password signs out your other devices
- [ ] Activity shows all of the above

Please note anything that's confusing or broken: that's the most useful feedback.

## 12. How RyProx works

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
- **Certificates** come from Let's Encrypt using the ACME protocol, via Go's `autocert` package. RyProx only allows certificates for domains you've configured, so a stranger pointing a random domain at your server can't make it request certificates.

**Code layout**

| Folder | What's in it |
| --- | --- |
| `cmd/ryprox` | The command-line program: `serve`, `reset-admin`, `healthcheck`, `version` |
| `internal/server` | Starts everything and wires the listeners together |
| `internal/proxy` | The proxy engine: routing, load balancing, health checks |
| `internal/certs` | Automatic HTTPS |
| `internal/api` | The dashboard's JSON API, login, sessions and security headers |
| `internal/auth` | Passwords, authenticator codes, recovery codes, rate limiting |
| `internal/config` | Checks everything you type before it's saved |
| `internal/store` | The SQLite database |
| `internal/secrets` | Encrypts sensitive values at rest |
| `internal/web/static` | The dashboard's HTML, CSS and JavaScript |

Run the tests with `make test`. They include attack cases: forged headers, Host-header tricks, replayed codes, cross-site requests and password guessing.
