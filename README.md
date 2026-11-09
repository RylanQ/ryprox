# RyProx

A self-hosted reverse proxy with a web dashboard. It serves services from your network under your own domains, with automatic HTTPS, and requires visitors to sign in before they reach them.

RyProx is in early development.

## Install

On a Linux server with ports 80 and 443 open and DNS for your domains pointing at it:

```sh
curl -fsSL https://raw.githubusercontent.com/RylanQ/ryprox/main/install.sh | sudo bash
```

The script installs RyProx with Docker or as a systemd service, sets up HTTPS, and prints a one-time setup code. Run it again to update. `--help` lists options for unattended installs.

To run it yourself instead:

```sh
make build
sudo setcap cap_net_bind_service=+ep bin/ryprox   # bind ports 80/443 without root
./bin/ryprox serve --data ./data
```

## First run

1. Find the setup code in the log (`docker logs ryprox` or `journalctl -u ryprox`).
2. Open the dashboard. It listens on `127.0.0.1:8081` only, so from your own computer use `ssh -L 8081:127.0.0.1:8081 user@server` and visit <http://localhost:8081>.
3. Enter the code, create the admin account, and scan the QR code with an authenticator app.
4. Under **Settings**, turn on automatic HTTPS and set a sign-in domain (for example `login.example.com`). Start with test certificates, then switch to real ones once they work.

## How it works

- **Routes** send a domain to one or more backend services. They're edited in the dashboard and apply immediately; invalid changes are rejected.
- **Routes are private by default.** Visitors are sent to the sign-in domain, sign in with a password and authenticator code, and are handed back to the site with a one-time code. Signing in never happens on a site's own domain, so a compromised app can't capture passwords. Every request is checked against the route's list of allowed people, and open connections are closed within seconds of access being removed. Public routes are an explicit choice.
- **People** are invited with a single-use link. Members can open the routes they're given; admins can also use the dashboard.
- Backends receive `X-RyProx-User` with the signed-in username, plus the usual `X-Forwarded-*` headers. Visitors can't set these themselves.

## Options

`ryprox serve` options, each also available as an environment variable:

| Option | Variable | Default |
| --- | --- | --- |
| `--data` | `RYPROX_DATA` | `./data` |
| `--http` | `RYPROX_HTTP` | `:80` |
| `--https` | `RYPROX_HTTPS` | `:443` |
| `--admin` | `RYPROX_ADMIN` | `127.0.0.1:8081` |
| `--log-level` | `RYPROX_LOG_LEVEL` | `info` |
| `--acme-directory` | `RYPROX_ACME_DIRECTORY` | Let's Encrypt |
| `--acme-ca` | `RYPROX_ACME_CA` | |

## Backups and recovery

Back up `ryprox.db` and `secret.key` from the data directory together; one is useless without the other.

If no admin can sign in, run `ryprox reset-admin --yes` and restart. Admin accounts are removed and a new setup code is printed; routes and members are kept.

## Development

```sh
make build
make test
```

## Security

Please report vulnerabilities privately through GitHub's **Security** tab rather than in a public issue.

## License

[AGPL-3.0](LICENSE)
