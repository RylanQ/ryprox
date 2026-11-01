# RyProx

**A self-hosted, identity-aware reverse proxy where everything is configured from the UI, and every feature is open source.**

> **Status: pre-alpha.** Nothing here is ready to put in front of real services yet. Follow the roadmap below to see progress.

## What RyProx will do

- **UI-first.** Add domains, routes, redirects and security settings from a web dashboard. No config files to edit; changes apply live with no restart.
- **Automatic HTTPS** with Let's Encrypt.
- **Sub-page routing:** send visitors to `test.com/page1`, route paths to different services, or serve a backend's sub-path.
- **CrowdSec built in** and managed from a Security tab: see attacks, ban and unban IPs.
- **Login in front of any app:** passkeys, two-factor, SSO, PIN codes, geo-blocking.
- **Tunnels:** expose services behind CGNAT or a firewall with no open ports.
- **Multiple sites and nodes** with load balancing and failover.
- **No paid edition.** Every feature ships in the open-source version.

## Roadmap

| Milestone | Focus |
| --- | --- |
| M0 | Legal and project setup |
| M1 | Core proxy, admin login, routes, HTTPS, live reload |
| M2 | Path routing, sub-pages, redirects |
| M3 | CrowdSec from the UI |
| M4 | Access control and identity |
| M5 | Tunnels and sites |
| M6 | Business-grade features (audit logs, SCIM, API) |
| M7 | High availability, browser SSH/RDP |

## Building from source

Requires Go 1.24 or newer.

```sh
make build       # builds ./bin/ryprox
make test        # runs the tests
make dev         # runs RyProx locally
./bin/ryprox version
```

## Security

Please report vulnerabilities privately. See [SECURITY.md](SECURITY.md).

## Contributing

Contributions are welcome once the project reaches its first release. See [CONTRIBUTING.md](CONTRIBUTING.md), and note the [clean-room policy](CLEAN-ROOM.md).

## Our promise

Every feature of RyProx will always be open source. If RyProx ever becomes a business, it will sell hosting and support, never a locked "enterprise" edition.

## Licence

RyProx is licensed under the [GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0-only).

RyProx is an independent project, written from scratch.
