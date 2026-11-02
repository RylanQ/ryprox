# Installation

## Requirements

- A Linux server reachable from the internet on ports 80 and 443. Let's Encrypt uses both to verify domain ownership.
- A DNS `A` record for each domain you want to serve, pointing at the server's public IP address. If the records are proxied through Cloudflare, set them to DNS only.
- An authenticator app (TOTP) for signing in.

## Install script

```sh
curl -fsSL https://raw.githubusercontent.com/RylanQ/ryprox/main/install.sh | sudo bash
```

The script asks for a dashboard domain and a Let's Encrypt email address, checks that ports 80 and 443 are free and that DNS resolves to the server, and optionally opens the firewall (ufw or firewalld). It installs RyProx with Docker if available, otherwise as a systemd service, and prints the setup code when RyProx has started.

Running the script again updates an existing installation and keeps its data.

To review the script before running it:

```sh
curl -fsSLO https://raw.githubusercontent.com/RylanQ/ryprox/main/install.sh
less install.sh
sudo bash install.sh
```

| Option | Description |
| --- | --- |
| `--docker`, `--native` | Install with Docker, or as a systemd service |
| `--domain NAME` | Serve the dashboard at `https://NAME` |
| `--email ADDRESS` | Let's Encrypt account email; enables automatic HTTPS |
| `--staging`, `--no-staging` | Start with Let's Encrypt test certificates (default: yes) |
| `--version VERSION` | Install a specific release (default: latest) |
| `--yes` | Don't prompt; use the given options and defaults |
| `--dry-run` | Print the actions without making changes |

## Docker Compose

```sh
git clone https://github.com/RylanQ/ryprox.git
cd ryprox
docker compose -f deploy/docker-compose.yml up -d --build
docker compose -f deploy/docker-compose.yml logs ryprox
```

The container runs as a non-root user with a read-only root filesystem and no capabilities. Data is kept in the `ryprox-data` volume.

## systemd

Download a release from the [releases page](https://github.com/RylanQ/ryprox/releases), or build from source with `make build`. Then, from the directory containing the binary and the repository's `deploy/` folder:

```sh
sudo useradd --system --home-dir /var/lib/ryprox --shell /usr/sbin/nologin ryprox
sudo install -m 0755 bin/ryprox /usr/local/bin/ryprox
sudo cp deploy/ryprox.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ryprox
```

The unit runs RyProx as the `ryprox` user with only the capability to bind ports below 1024, and limits writes to `/var/lib/ryprox`.

## First run

On first start, RyProx prints a setup code to its log:

```
First-time setup code:  AD4B-HHAX-9F2J
```

Read it with `docker logs ryprox` or `journalctl -u ryprox`. Open the dashboard, enter the code, and create the admin account. You will be asked to scan a QR code with your authenticator app and to save ten recovery codes. The setup code only works once.

## Opening the dashboard

The dashboard listens on `127.0.0.1:8081` and is not reachable from other machines. Use an SSH tunnel:

```sh
ssh -L 8081:127.0.0.1:8081 user@server
```

and open <http://localhost:8081>. Once HTTPS is enabled you can also give the dashboard its own domain; see [HTTPS](https.md#dashboard-domain).

## Command-line options

`ryprox serve` accepts the following options. Each can also be set with the environment variable shown.

| Option | Variable | Default | Description |
| --- | --- | --- | --- |
| `--data` | `RYPROX_DATA` | `./data` | Data directory |
| `--http` | `RYPROX_HTTP` | `:80` | HTTP listen address |
| `--https` | `RYPROX_HTTPS` | `:443` | HTTPS listen address |
| `--admin` | `RYPROX_ADMIN` | `127.0.0.1:8081` | Dashboard listen address |
| `--log-level` | `RYPROX_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error` |
| `--log-format` | `RYPROX_LOG_FORMAT` | `text` | `text` or `json` |
| `--acme-directory` | `RYPROX_ACME_DIRECTORY` | Let's Encrypt | ACME directory URL |
| `--acme-ca` | `RYPROX_ACME_CA` | | PEM file of root certificates for the ACME server |

Other commands:

| Command | Description |
| --- | --- |
| `ryprox init` | Write HTTPS settings before first start (used by the install script) |
| `ryprox reset-admin --yes` | Remove all admin accounts; see [recovery](operations.md#recovering-access) |
| `ryprox healthcheck` | Exit with status 0 if the local instance is responding |
| `ryprox version` | Print version information |

## Uninstalling

Docker (as installed by the script):

```sh
docker rm -f ryprox
docker volume rm ryprox-data   # deletes all data
```

Docker Compose:

```sh
docker compose -f deploy/docker-compose.yml down --volumes   # deletes all data
```

systemd:

```sh
sudo systemctl disable --now ryprox
sudo rm /usr/local/bin/ryprox /etc/systemd/system/ryprox.service
sudo rm -r /var/lib/ryprox     # deletes all data
sudo userdel ryprox
```
