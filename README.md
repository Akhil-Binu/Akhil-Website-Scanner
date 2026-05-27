# Akhil WebGuard - Enterprise Cybersecurity Suite 🛡️

Akhil WebGuard is a state-of-the-art, lightning-fast web vulnerability scanner, footprinting tool, and comprehensive cybersecurity platform. Built with Node.js, it performs concurrent asynchronous scans to evaluate the security posture of any target URL or source code within seconds.

Akhil WebGuard has evolved from a passive HTTP header scanner into a massive "Red Team" toolkit powered by Google Gemini AI, featuring active exploitation, authenticated scanning, and enterprise-grade PDF reporting.

---

## 🌟 Massive Feature Set

### 1. 🔐 Authenticated Scanning Mode (Custom Headers)
- Target internal, logged-in, or private dashboards by passing custom HTTP Headers or Cookies directly into the UI.
- The engine dynamically injects your authentication tokens into **all 15 scanning modules**, allowing deep penetration of restricted areas.

### 2. 💻 Code Auditor (SAST Engine)
- A dedicated **Static Application Security Testing (SAST)** mode powered by Gemini AI.
- Paste raw backend source code (Node.js, Python, PHP, etc.) to instantly detect hardcoded passwords, SQL injection flaws, insecure API endpoints, and weak cryptography before the code is even deployed.

### 3. 🐍 Automated Exploit PoC Generator
- When the active DAST engine discovers a vulnerability (SQLi, XSS, SSRF), a **"Generate PoC"** button appears.
- Click it, and Gemini AI instantly writes a custom Python Exploit Script using the `requests` library to actively demonstrate how an attacker would exploit the exact vulnerable parameter found on your server.

### 4. 📋 Global Compliance Mapping
- The results dashboard maps your security posture to global frameworks.
- Automatically flags **OWASP Top 10 (A05:2021 Security Misconfiguration)** for missing headers.
- Flags **OWASP Top 10 (A03:2021 Injection)** for active DAST exploits.
- Flags **PCI-DSS Requirement 4.1** for weak or missing TLS configurations.

### 5. 📄 Enterprise PDF Reporting
- Generate massive, exhaustive, multi-page, text-selectable **Executive Security Assessment Reports**.
- The PDF includes 12 comprehensive sections: Cover Page, AI Insights, Active DAST Exploits, HTTP Headers, SSL/TLS Certificates, Infrastructure Posture, Compliance Violations, CSP Assessment, Cookie Security, Advanced DNS Security, Directory Fuzzing, and DOM Secrets.

### 6. 🔥 Active DAST Exploitation Engine
When a URL with parameters is provided (e.g., `?id=1`), Akhil WebGuard automatically injects malicious payloads to verify exploitability:
- **SQL Injection (SQLi)**: Fires SQL payloads and fingerprints the response for database syntax errors.
- **Cross-Site Scripting (XSS)**: Injects raw `<script>` tags to check for unsanitized payload reflection.
- **Directory Traversal (LFI)**: Attempts to break out of the web root to access sensitive files.
- **Server-Side Request Forgery (SSRF)**: Hunts for internal cloud credential leaks.

### 7. 🕵️ Red Team Offensive Scanners
- **Targeted Directory Fuzzer**: Probes for critical exposed files (`/.env`, `/.git/config`) and modern API threats (Swagger/OpenAPI documentation).
- **Subdomain Takeover Detection**: Enumerates subdomains via `crt.sh` to flag Dangling DNS vulnerabilities.
- **WAF Fingerprinting**: Detects Cloudflare, AWS WAF, Akamai, Imperva, and Sucuri.
- **Open Port Scanner**: Uses raw Node.js sockets to aggressively probe 10 critical service ports.
- **Broken Link Hijacking**: Flags dead outbound domains that an attacker could register.

### 8. 🧠 Google Gemini AI Intelligence
- **Phishing & Scam Assessment**: Evaluates homepage copywriting for social engineering indicators.
- **Malicious JavaScript Analysis**: Evaluates inline `<script>` tags for obfuscated tracking malware or crypto-miners.
- **Attack Chain Generation**: Synthesizes discovered vulnerabilities to write a custom narrative of how a hacker could breach the target.
- **Interactive Chat Widget**: Converse directly with the AI using your unique scan JSON payload as context to ask specific security questions.

---

## 🚀 How to Run Locally

Akhil WebGuard is designed to be lightweight and fast.

### Prerequisites
- [Node.js](https://nodejs.org/) installed on your machine.

### Installation & Execution
1. Open your terminal and navigate to the project directory:
   ```bash
   cd "Akhil Website Scanner"
   ```

2. Install the required Node.js dependencies:
   ```bash
   npm install express axios cheerio
   ```

3. Start the Akhil WebGuard backend engine:
   ```bash
   node server.js
   ```

4. Open your browser and navigate to the dashboard:
   **[http://localhost:3000](http://localhost:3000)**

### Usage Modes
- **🌍 Web Scanner (DAST)**: Enter a live URL to run active infrastructure footprinting, payload injection, and compliance mapping. Toggle "Advanced Options" to provide Auth Headers.
- **💻 Code Auditor (SAST)**: Switch tabs to paste raw source code and audit logic vulnerabilities offline.

---
*Disclaimer: Akhil WebGuard is built for educational purposes and authorized security auditing. Do not scan targets without explicit permission.*
