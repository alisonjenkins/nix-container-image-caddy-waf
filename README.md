# nix-container-image-caddy-waf

A web application firewall container: [Caddy](https://caddyserver.com/) with
the [Coraza](https://coraza.io/) WAF and the
[OWASP Core Rule Set](https://coreruleset.org/) (CRS), built with Nix.

It replaces the `owasp/modsecurity-crs` nginx image in the home cluster. One
pod sits in front of each app, between the Gateway and the app. Caddy, Coraza
and the rate limiter are all Go, so the HTTP parser and the rule engine are
memory-safe.

## What is in the image

| Part | Version | Notes |
|---|---|---|
| Caddy | nixpkgs 26.05 | built with `caddy.withPlugins` |
| coraza-caddy | v2.6.2 | Coraza v3, the `coraza_waf` directive |
| caddy-ratelimit | v0.1.0 | the `rate_limit` directive |
| CRS | v4.30.0 | same version as the ModSecurity image it replaces |

Bump a plugin by changing its version in `flake.nix`, then the `hash`.

## Configuration

Everything app-specific comes from environment variables or mounted files.
The image runs as uid 101 on port 8080 with a read-only root filesystem; it
needs a writable `/tmp` (an emptyDir).

| Variable | Default | Meaning |
|---|---|---|
| `BACKEND` | (required) | upstream URL |
| `TRUSTED_PROXIES` | `10.42.0.0/16` | CIDRs whose `X-Forwarded-For` is believed |
| `RULE_ENGINE` | `On` | `DetectionOnly` logs without blocking |
| `BLOCKING_PARANOIA` | `1` | CRS paranoia level |
| `ANOMALY_INBOUND` | `5` | CRS inbound anomaly threshold |
| `ALLOWED_METHODS` | `GET HEAD POST OPTIONS` | CRS `tx.allowed_methods` |
| `REQ_BODY_NOFILES_LIMIT` | `1048576` | max bytes of a body without file uploads |
| `REQ_BODY_LIMIT_ACTION` | `Reject` | `Reject` or `ProcessPartial` past 12.5 MiB |
| `FORWARDED_PROTO` / `FORWARDED_PORT` | `https` / `443` | sent upstream |

| Mount | Contents |
|---|---|
| `/etc/caddy-waf/rules/*.conf` | SecLang exclusions, loaded before CRS |
| `/etc/caddy-waf/site.d/*.caddy` | Caddy handlers run before the WAF, such as `rate_limit` |
| `/etc/caddy-waf/proxy.d/*.caddy` | extra `reverse_proxy` subdirectives, such as upstream TLS |

`/healthz` answers 200 before the WAF, for kubelet probes.

## Differences from the ModSecurity image

- **Body size without files.** Coraza parses `SecRequestBodyNoFilesLimit` but
  does not enforce it ([coraza#896](https://github.com/corazawaf/coraza/issues/896)).
  Caddy enforces it instead: a non-multipart body over
  `REQ_BODY_NOFILES_LIMIT` gets 413 before Coraza reads it.
- **Rate limits** use a sliding window (`events N window 1m`), not nginx's
  leaky bucket with a burst.
- **Client address.** Caddy reads `X-Forwarded-For` from right to left and
  stops at the first untrusted hop, so a client cannot spoof it. Rate limits
  key on `{client_ip}`.
- **Logs.** The access log drops query strings, `Referer`, `Authorization`,
  `Cookie`, `X-Api-Key` and `Set-Cookie`. The audit log (parts A, H and Z, as
  JSON on stdout) has Coraza's shape, not ModSecurity's.
- Directives Coraza lacks are left out: PCRE limits, `SecUnicodeMapFile`,
  `SecStatusEngine`, `SecCookieFormat`, `SecRequestBodyJsonDepthLimit`.

## Gotchas

- CRS rule 920450 blocks the `Expect` header. curl sends
  `Expect: 100-continue` for bodies over 1 MB, so test with `-H 'Expect:'`.
  ModSecurity behaves the same.
- CRS rule 920350 adds 3 to the anomaly score when `Host` is an IP address.

## Build and test

```sh
just build   # build and load localhost/caddy-waf:latest
just test    # smoke test: attacks blocked, exclusions, rate limit, logs
```

CI runs the same smoke test. Every push to `main` publishes
`ghcr.io/alisonjenkins/caddy-waf:<UTC date>_<time>-<sha7>` and `latest`.
