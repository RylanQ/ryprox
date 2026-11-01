# RyProx

**A self-hosted reverse proxy where everything is configured from the UI, and every feature is open source.**

> **Status: pre-alpha.** Not ready to put in front of real services yet.

## Planned features

- Add domains, routes and redirects from a web dashboard; changes apply live, no config files
- Automatic HTTPS
- Sub-page and path-based routing
- CrowdSec built in, managed from the UI
- Login in front of any app: passkeys, two-factor, SSO
- Tunnels for services behind CGNAT or a firewall
- Multiple sites and nodes with load balancing

## Build

Requires Go 1.24+.

```sh
make build            # builds ./bin/ryprox
make test             # runs the tests
make dev              # runs RyProx on 127.0.0.1:8080
```

## Security

Please report vulnerabilities privately. See [SECURITY.md](SECURITY.md).

## Licence

[AGPL-3.0](LICENSE)
