# RyProx

RyProx is a self-hosted reverse proxy with a web dashboard. It puts services from your network on the internet under your own domains, with automatic HTTPS, and requires visitors to sign in before they can open them.

> RyProx is in early development. Expect breaking changes until 1.0.

## Features

- Routes, certificates and users are managed in the dashboard. There are no configuration files, and changes apply without a restart.
- Routes are private by default: visitors sign in with a password and an authenticator code, and every request is checked against the route's access list.
- Automatic HTTPS certificates from Let's Encrypt or any ACME server.
- Load balancing and failover across several backends, with health checks.
- WebSocket support and request/response header rules.
- A single static binary with an embedded SQLite database.

## Installation

On a Linux server with ports 80 and 443 open:

```sh
curl -fsSL https://raw.githubusercontent.com/RylanQ/ryprox/main/install.sh | sudo bash
```

The script installs RyProx with Docker or as a systemd service and prints a one-time setup code. See [installation](docs/installation.md) for other methods.

## Documentation

- [Installation](docs/installation.md)
- [Routes](docs/routes.md)
- [Access control](docs/access-control.md)
- [HTTPS](docs/https.md)
- [Operations](docs/operations.md): backups, updates, recovery and troubleshooting
- [Architecture](docs/architecture.md)

## Building

Requires Go 1.26 or later.

```sh
make build   # bin/ryprox
make test
```

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

[AGPL-3.0](LICENSE)
