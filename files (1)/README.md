# SixCheck – IPv6 Website and Dependency Readiness Auditor

AIORI Hackathon 3 · Problem statement PS-027 (Internet Measurement) · Team ID A3-PS027-TC126

SixCheck assesses a domain's IPv6 readiness across eight weighted checks: apex AAAA, www AAAA, nameservers, mail (MX), HTTPS over IPv6, TLS over IPv6, third-party dependencies and an IPv6-only (DNS64/NAT64) test. It produces a 0–100 score, a dependency table and a prioritised fix list.

## Status

The front end is complete. Audit results are **simulated** and repeatable per domain. Live probing (DNS, TCP and TLS over IPv6) needs the measurement backend described in the System design section of the site.

## Run locally

Open `index.html` in a browser. There is no build step and no dependencies.

## Deploy

Hosted with GitHub Pages from the `main` branch, root folder.

## Standards referenced

RFC 8200, RFC 3596, RFC 3901 / RFC 9386, RFC 8305, RFC 6146 / RFC 6147, RFC 6724.
