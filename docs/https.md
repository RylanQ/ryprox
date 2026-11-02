# HTTPS

RyProx obtains and renews certificates automatically using ACME, from Let's Encrypt by default. Certificates are only requested for domains of enabled routes and the dashboard domain; requests for any other name are refused.

## Enabling automatic HTTPS

1. Make sure each domain resolves to the server and ports 80 and 443 are reachable from the internet.
2. Under **Settings → HTTPS**, select **Automatic HTTPS** and enter an email address. Let's Encrypt uses it for expiry notices.
3. Leave **Use test certificates** on for the first attempt. Test certificates aren't trusted by browsers, but Let's Encrypt's test service has much higher rate limits, which helps while DNS and firewall settings are being fixed.
4. Save, and check **Certificates**. Each domain should show *Test certificate* within a minute.
5. Turn **Use test certificates** off and save to switch to trusted certificates.

Certificates are renewed about 30 days before they expire. Test and production certificates are stored separately.

Select **HTTP only** if TLS is terminated by another proxy in front of RyProx.

## Dashboard domain

With automatic HTTPS enabled, set **Admin dashboard domain** to serve the dashboard on a domain such as `ryprox.example.com`. The dashboard is then available on that domain over HTTPS only, in addition to `127.0.0.1:8081`. A dashboard domain cannot be used by a route.

## Other certificate authorities

To use a different ACME server, such as a private step-ca instance, start RyProx with `--acme-directory` and, if the server uses a private root certificate, `--acme-ca`:

```sh
ryprox serve --acme-directory https://ca.internal/acme/acme/directory --acme-ca /etc/ryprox/root.pem
```

This replaces Let's Encrypt for all certificates. The *test certificates* setting is ignored.

## Troubleshooting

| Status | Cause |
| --- | --- |
| *Getting certificate* for several minutes | Usually DNS or the firewall. Check that `dig +short <domain>` returns the server's address and that port 80 is open. |
| *Certificate failed* | The error is shown next to the domain. Fix the cause and select **Try again**. |
| Browser warning with a valid-looking certificate | Test certificates are still enabled. |
