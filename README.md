# Sentinel

Sentinel is a Next.js security audit dashboard that streams results for website checks, local network scans, GitHub exposure reviews, and OSINT-style analysis.

## What It Covers

- `src/pages/` for the UI and API endpoints
- `src/utils/` for the scanners, diffing, throttling, and result aggregation
- `docker-compose.yml` for the local containerized stack
- `docs/deployment.md` for deployment and environment notes

## Highlights

- Streaming scan output with categorized findings
- Separate views for website audit, local network checks, and GitHub scanning
- Support for browser-assisted checks, WHOIS, DNS, SSL, and Nmap-style workflows

## Usage

```bash
npm install
npm run dev
```

Then open the app in a browser and start a scan from the dashboard.
