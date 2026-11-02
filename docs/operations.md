# Operations

## Data directory

| Path | Contents |
| --- | --- |
| `ryprox.db` | Routes, settings, users, sessions and the activity log (SQLite) |
| `secret.key` | Key used to encrypt authenticator secrets in the database |
| `certs/` | Certificates and the ACME account key |

The data directory is `/data` in the container (the `ryprox-data` volume), `/var/lib/ryprox` with systemd, or the value of `--data`.

## Backups

Back up `ryprox.db` and `secret.key` together. The database can't be used to sign in without the key, and the key is useless without the database. Certificates can be re-issued and don't need backing up.

For a consistent copy of a running instance, use SQLite's backup command:

```sh
sqlite3 /var/lib/ryprox/ryprox.db ".backup '/backups/ryprox.db'"
cp /var/lib/ryprox/secret.key /backups/
```

## Updating

Run the install script again, or rebuild and restart:

```sh
docker compose -f deploy/docker-compose.yml up -d --build
```

Database migrations run automatically on start. Downgrading to an older version after a migration is not supported; restore a backup instead.

## Logs

RyProx logs to standard error. Use `docker logs ryprox` or `journalctl -u ryprox`. Set `--log-format json` for structured output and `--log-level debug` for more detail.

## Recovering access

A user who loses their authenticator can sign in with a recovery code. An admin can also remove the user and send a new invite.

If no admin can sign in, run the following on the server and restart RyProx:

```sh
ryprox reset-admin --yes --data /var/lib/ryprox
# Docker:
docker run --rm -v ryprox-data:/data <image> reset-admin --yes
```

This deletes all admin accounts. Routes, settings and members are kept. A new setup code is printed on the next start. Add the new admin to the access lists of private routes again as needed.

## Troubleshooting

| Problem | Cause |
| --- | --- |
| No setup code in the log | Setup has already been completed. Use `reset-admin` if needed. |
| `bind: permission denied` on port 80 or 443 | The binary lacks permission to bind low ports. Use the systemd unit, or run `setcap cap_net_bind_service=+ep /usr/local/bin/ryprox`. |
| `address already in use` | Another program, often another web server, is using port 80 or 443. |
| 502 for a service on the Docker host | Inside the container, `localhost` refers to the container. Use the host's LAN address. |
| Redirect loops or broken links in an application | Enable *Pass the original domain to the service* and set the application's external URL to its `https://` address. |
| *Signing in needs HTTPS* | Private routes don't accept passwords over plain HTTP. Enable HTTPS. |
| *Too many attempts* | Sign-in is rate limited; the message shows when to retry. |

See also [HTTPS troubleshooting](https.md#troubleshooting).
