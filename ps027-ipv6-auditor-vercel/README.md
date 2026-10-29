# SixCheck – IPv6 Website and Dependency Readiness Auditor

AIORI Hackathon 3 · PS-027 (Internet Measurement) · Team ID A3-PS027-TC126

Audits a domain for IPv6 readiness: apex and www AAAA, nameservers, mail hosts, HTTPS and TLS over IPv6, third-party dependencies and an IPv6-only analysis. Gives a 0–100 score and a prioritised fix list.

## Structure

- `public/` – frontend (`index.html`, `css/style.css`, `js/app.js`)
- `api/audit.js` – backend, a Vercel serverless function: `GET /api/audit?domain=example.org`
- `vercel.json`, `package.json` – deployment config (no dependencies to install)

## Run locally

    npm i -g vercel
    vercel dev

Open http://localhost:3000. Plain `index.html` also works, but without the backend it shows simulated demo results.

## Deploy to Vercel

Push this folder to GitHub, then on vercel.com choose **Add New, Project**, import the repository and press **Deploy**. Leave the framework as "Other" and the build command empty. Or run `vercel --prod` from this folder.

## Notes

- Full IPv6 testing: see `DEPLOY-VPS.md` (Dockerfile, docker-compose and `server.js` for a VPS with IPv6).
- Vercel functions have no outbound IPv6. The backend detects this and marks "HTTPS on IPv6" and "TLS on IPv6" as Not tested (excluded from the score). To run those two checks, host `api/audit.js` on a server with IPv6 (for example a VPS).
- The backend blocks private and loopback addresses to prevent server-side request forgery. It does not rate limit; add rate limiting before public use.
