# Contributing to RyProx

Thanks for your interest! RyProx is pre-alpha and currently maintained by one person, so please open an issue to discuss before starting large changes.

## Before you start

- Read the [clean-room policy](CLEAN-ROOM.md). It is short and it matters.
- For a new feature, add or update a spec in [`docs/specs/`](docs/specs/) first.

## Sign your commits (DCO)

Every commit must be signed off to certify the [Developer Certificate of Origin](https://developercertificate.org/): that you wrote the change, or otherwise have the right to submit it under the project's licence.

```sh
git commit -s -m "Add route validation"
```

This adds a `Signed-off-by: Your Name <you@example.com>` line.

> **Note for future contributors:** before outside contributions are accepted, RyProx will adopt a Contributor Licence Agreement (CLA). This keeps the option to offer commercial licences alongside the AGPL, which helps fund the project. Every feature stays open source either way.

## Development

```sh
make build   # build ./bin/ryprox
make test    # run tests with the race detector
make lint    # go vet + golangci-lint (if installed)
make dev     # run locally
```

## Pull requests

- Keep them small and focused on one thing.
- Include tests. Anything touching authentication, routing or request handling needs tests for the attack cases too, not just the happy path.
- Run `make test lint` before pushing.
- Explain *why* in the description, not just *what*.

## Security issues

Never in public issues or pull requests. See [SECURITY.md](SECURITY.md).
