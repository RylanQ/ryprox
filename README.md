# RyProx

**A self-hosted reverse proxy where everything is configured from the UI, and every feature is open source.**

> **Status: alpha.** Milestone 1 is done and ready for real-world testing. Expect rough edges.

## What it does today

- **Routes from the dashboard**: send `photos.example.com` to `http://192.168.1.10:2342`. Changes go live instantly; no config files, no restarts.
- **Automatic HTTPS** with Let's Encrypt, including a test-certificate mode and an optional HTTPS admin domain.
- **Several services per route** with load balancing or failover, plus health checks.
- **WebSockets**, header rules, and support for self-signed backends.
- **Secure by default**: two-step sign-in, single-use codes, lockout on guessing, encrypted secrets, a full activity log, and a dashboard that only listens on the server itself unless you give it a domain.

## Coming next

Sub-page routing and redirects, CrowdSec built in, login in front of any app (passkeys, SSO), tunnels for services behind CGNAT, and multiple nodes.

## Get started

On a Linux server, run:

```sh
curl -fsSL https://raw.githubusercontent.com/RylanQ/ryprox/main/install.sh | sudo bash
```

It asks a few questions, sets up HTTPS, and prints your setup code. Read the **[guide](docs/GUIDE.md)** for everything else, including installing by hand.

## Build from source

Requires Go 1.26+.

```sh
make build     # ./bin/ryprox
make test      # all tests, including security tests
make dev       # run locally on high ports
```

## Security

Please report vulnerabilities privately. See [SECURITY.md](SECURITY.md).

## Licence

[AGPL-3.0](LICENSE)
