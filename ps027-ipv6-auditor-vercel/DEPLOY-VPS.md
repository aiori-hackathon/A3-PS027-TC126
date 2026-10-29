# Deploy on a VPS with IPv6 (all 8 checks)

Vercel has no outbound IPv6, so two checks show "Not tested" there. On a VPS with a public IPv6 address every check runs.

## 1. Get a VPS
Any Linux VPS with a public IPv6 address (check with `curl -6 https://ifconfig.co`, it must print an IPv6 address).

## 2. Install Docker and copy the project
    curl -fsSL https://get.docker.com | sh
    git clone https://github.com/<your-username>/ps027-ipv6-auditor.git
    cd ps027-ipv6-auditor

## 3. Start it
    docker compose up -d --build

Open `http://<server-ip>:3000`. The server listens on IPv4 and IPv6, so `http://[<server-ipv6>]:3000` works too. Open port 3000 in the firewall if needed.

## 4. Confirm IPv6 works
    curl "http://localhost:3000/api/audit?domain=wikipedia.org"

The response must contain `"ipv6Egress":true`. If it says false, the VPS has no working IPv6 route.

## 5. HTTPS with a domain (optional)
Point a domain at the server, install Caddy and use this Caddyfile:

    audit.yourdomain.com {
        reverse_proxy localhost:3000
    }

Then set `TRUST_PROXY=1` in `docker-compose.yml` and run `docker compose up -d` again, so rate limiting sees each visitor's real IP.

## Without Docker
    node server.js        # Node 18 or newer, no npm install needed

The server allows 20 audits per minute per client.
