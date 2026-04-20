# Sentinel | Professional Security Audit & Intelligence Station

Sentinel is a comprehensive security auditing platform designed for professional researchers, system administrators, and security teams. It provides real-time insights into web security postures, internal network configurations, and repository exposure risks.

## 🛡️ Responsible Use Policy

Sentinel is developed for ethical security research and authorized audits. By using this software, you agree to:
- Only perform assessments on systems and networks where you have explicit, written authorization.
- Adhere to the principles of responsible disclosure.
- Comply with all local and international data protection and computer misuse laws.

**Disclaimer:** The authors of Sentinel are not responsible for any damage caused by unauthorized use or misconfiguration of this tool. Use of this software signifies your agreement to these terms.

---

## 🚀 Key Features

- **Security Assessment**: Live analysis of web headers, TLS/SSL configurations, cookie security, and domain policy (DMARC/SPF/WHOIS).
- **Internal Audit**: Deep network discovery and security risk mapping for private infrastructure.
- **Exposure Monitor**: Automated monitoring of repositories for potentially exposed credentials and environment configurations.
- **Intelligence Suite**: Real-time crawling and network topology discovery to identify hidden assets and risks.

---

## 🛠️ Getting Started

First, install dependencies:

```bash
npm install
```

Then, run the development server:

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) with your browser to access the dashboard.

## 📁 Project Structure

- `src/pages`: React components and API routes.
- `src/utils/securityScanner.ts`: Core security analysis engine.
- `src/utils/githubScanner.ts`: Repository exposure monitor logic.
- `src/utils/nmapScanner.ts`: Internal network audit engine.

## 🐳 Deployment & Docker

Sentinel provides a slim Docker image for easy deployment.

### Docker Compose (Local Development)

The easiest way to run the full stack locally (including dynamic DOM analysis) is using Docker Compose. Create a `docker-compose.yml`:

```yaml
version: '3.8'
services:
  sentinel:
    image: ghcr.io/your-org/sentinel:latest
    ports:
      - "3000:3000"
    environment:
      - BROWSERLESS_URL=ws://browserless:3000
    cap_add:
      - NET_RAW
    depends_on:
      - browserless

  browserless:
    image: browserless/chrome:latest
    ports:
      - "3000:3000"
    environment:
      - MAX_CONCURRENT_SESSIONS=10
```

Run with `docker-compose up -d`.

### Kubernetes Deployment (Production)

To deploy Sentinel in a Kubernetes cluster alongside a remote Chromium node, use the following example. Notice that `NET_RAW` is added to capabilities to allow deep Nmap stealth scans.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sentinel
spec:
  replicas: 1
  selector:
    matchLabels:
      app: sentinel
  template:
    metadata:
      labels:
        app: sentinel
    spec:
      containers:
        - name: sentinel
          image: ghcr.io/your-org/sentinel:latest
          ports:
            - containerPort: 3000
          env:
            - name: BROWSERLESS_URL
              value: "ws://browserless-service:3000"
          securityContext:
            capabilities:
              add:
                - NET_RAW # Required for raw socket scans in Nmap (-sS, -O, etc.)

---
# Separate Browserless Deployment for DOM Analysis
apiVersion: apps/v1
kind: Deployment
metadata:
  name: browserless
spec:
  replicas: 1
  selector:
    matchLabels:
      app: browserless
  template:
    metadata:
      labels:
        app: browserless
    spec:
      containers:
        - name: browserless
          image: browserless/chrome:latest
          ports:
            - containerPort: 3000
```

## ⚖️ Legal

Sentinel is provided under the terms specified as an open-source project. This tool is provided "as is" without warranty of any kind.

# ⚠️ LEGAL DISCLAIMER & EDUCATIONAL USE ONLY ⚠️

> **IMPORTANT:** This project is provided strictly for **EDUCATIONAL AND RESEARCH PURPOSES ONLY**. 
> 
> The author(s) and contributors of this project **DO NOT assume any responsibility or liability** for any misuse, damage, or illegal activities conducted using this tool. 
> 
> **NEVER** use this tool against any target (domain, network, OR IP) without explicit, written authorization from the owner. Unauthorized scanning or testing of networks is illegal and unethical. Use this software at your own risk.
