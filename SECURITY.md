# Security policy

RyProx sits in front of people's private services, so we take security reports seriously.

## Reporting a vulnerability

**Please do not open a public issue.**

Report privately through GitHub: go to the **Security** tab of this repository and click **Report a vulnerability**.

<!-- TODO: add a dedicated security contact email once one exists, e.g. security@ryprox.dev -->

Please include:

- what the issue is and what an attacker could do with it
- steps to reproduce, or a proof of concept
- the RyProx version or commit you tested

## What to expect

| Step | Target |
| --- | --- |
| Acknowledge your report | within 72 hours |
| Initial assessment | within 7 days |
| Fix for critical issues | as fast as possible, aiming for 14 days |

We will keep you updated, credit you in the advisory (unless you prefer not), and publish a GitHub Security Advisory once a fix is released.

## Supported versions

RyProx is pre-alpha. Only the latest commit on `main` receives fixes. This table will be updated once releases begin.

## Scope

In scope: the RyProx binary, container images, agent and anything in this repository.

Out of scope: vulnerabilities in third-party dependencies that are already publicly known (please report those upstream), and issues that require an already-compromised host.

## Safe harbour

We will not take legal action against anyone who reports in good faith, avoids harming users or their data, and gives us reasonable time to fix the issue before disclosure.
