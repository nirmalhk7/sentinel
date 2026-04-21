<div align="center">
  <img src="https://raw.githubusercontent.com/nirmalhk7/sentinel/main/public/logo.png" alt="Sentinel Logo" width="120" />
  <h1>SENTINEL</h1>
  <p><strong>Professional-Grade Security Audit & Intelligence Station</strong></p>

  <p>
    <img src="https://img.shields.io/badge/Status-Active-success?style=for-the-badge" alt="Status" />
    <img src="https://img.shields.io/badge/License-FOSS-blue?style=for-the-badge" alt="License" />
    <img src="https://img.shields.io/badge/Built%20With-Next.js-black?style=for-the-badge" alt="Built With" />
  </p>

  <h4>The unified security dashboard for modern infrastructure audits.</h4>
</div>

---

## 📖 Overview

**Sentinel** is an open-source security auditing platform designed for professional security researchers, system administrators, and DevSecOps teams. It consolidates multiple scanning methodologies—from deep network discovery to repository exposure monitoring—into a single, high-performance dashboard.

Whether you are auditing internal networks, verifying public-facing configurations, or monitoring repository hygiene, Sentinel provides the real-time intelligence needed to maintain a robust security posture.

---

## ✨ Key Features

### 🔍 Security Assessment (DAST)
- **Header Analysis**: Real-time evaluation of security headers (CSP, HSTS, X-Frame-Options).
- **SSL/TLS Auditing**: Comprehensive certificates and cipher suite validation via Nmap & OpenSSL.
- **Dynamic DOM Probing**: Headless Chromium integration to detect client-side vulnerabilities in rendered JavaScript.
- **Protocol Policy**: Automated checks for SPF, DMARC, and WHOIS registration data.

### 🌐 Internal Infrastructure Audit
- **Stealth Port Scanning**: Advanced Nmap integration for deep service discovery across multi-zone networks.
- **Security Mapping**: Automated mapping of internal service risks and misconfigurations.
- **Topology Discovery**: Visualizing network relationships and potential pivot points.

### 🐙 Exposure Monitor
- **Repository Scanning**: Deep-dive surveillance of GitHub repositories for exposed credentials, `.env` files, and secrets.
- **Pattern Matching**: Advanced regex engine designed to catch high-entropy tokens and configuration leaks.
- **OSINT Intel**: Gathering public metadata to build a comprehensive risk profile of your digital footprint.

---

## 🚀 Getting Started

### Prerequisites

Sentinel requires the following system-level tools to perform deep scanning:
- `nmap`: Required for network discovery.
- `whois`: Required for domain audit.
- `traceroute`: Required for network path analysis.

### Quick Start (Local Development)

1. **Clone & Install**
   ```bash
   git clone https://github.com/nirmalhk7/sentinel.git
   cd sentinel
   npm install
   ```

2. **Environment Setup**
   Configure your `.env` for repository monitoring:
   ```bash
   GITHUB_TOKEN=your_token_here
   ```

3. **Launch**
   ```bash
   npm run dev
   ```

Open [http://localhost:3000](http://localhost:3000) to access your new security station.

---

## 🐳 Deployment

Sentinel is built for containerized environments, ensuring scale and consistency across production clusters.

### Kubernetes Best Practices
The Sentinel Docker image is optimized to be **slim** (~250MB). For production, we recommend running Chromium as a separate microservice:

```yaml
# Deployment snippet targeting sentinel with NET_RAW capability
securityContext:
  capabilities:
    add:
      - NET_RAW # Enables stealth nmap scanning
env:
  - name: BROWSERLESS_URL
    value: "ws://browserless-service:3000"
```

> [!TIP]
> Refer to the [Deployment Guide](./docs/deployment.md) for full Docker Compose and Kubernetes manifests.

---

## 🛡️ Responsible Use & Ethical Policy

Sentinel is a powerful tool designed for **authorized security audits and educational research only**. 
By utilizing this software, you commit to:
- **Authorization First**: Only scan systems you own or have explicit written permission to audit.
- **Do No Harm**: Avoid disruptive scanning on production systems without prior impact assessment.
- **Responsible Disclosure**: Report found vulnerabilities to the affected parties privately and ethically.

---

## ⚖️ Legal Disclaimer

> [!CAUTION]
> This project is provided strictly for **EDUCATIONAL AND RESEARCH PURPOSES ONLY**. 
> The authors and contributors assume **no liability** for misuse or illegal use of this software. Unauthorized scanning of third-party networks is a violation of international laws and may result in criminal prosecution.

---

<p align="center">
  Built with ❤️ for the security community.
</p>
