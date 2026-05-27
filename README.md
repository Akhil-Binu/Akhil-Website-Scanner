# Akhil WebGuard - Intelligent Cybersecurity Platform 🛡️

Akhil WebGuard is a state-of-the-art, lightning-fast web vulnerability scanner, footprinting tool, and Active DAST (Dynamic Application Security Testing) engine. Built with Node.js, it performs concurrent asynchronous scans to evaluate the security posture of any given target URL within seconds.

Akhil WebGuard has evolved from a passive HTTP header scanner into a comprehensive "Red Team" toolkit powered by Google Gemini AI.

---

## 🌟 Massive Feature Set

### 1. Passive Footprinting & Security Headers
- **Header Analysis**: Strict-Transport-Security (HSTS), Content-Security-Policy (CSP), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
- **Auto-Remediation**: Generates ready-to-paste secure configuration blocks for **Nginx, Apache, Express.js, and Next.js**.
- **SSL/TLS Deep Analysis**: Certificate validation, days remaining, cipher suites, TLS version (detecting deprecated TLSv1.0/1.1), ALPN HTTP/2 support, and Self-Signed certificate detection.

### 2. Advanced DOM & HTML Security
- **DOM Sinks & XSS Vectors**: Detects unsafe usage of `innerHTML`, `document.write`, and `eval()`.
- **Hardcoded Secrets**: Uses heuristics to detect leaked AWS Keys (AKIA), Google API Keys, and JWTs in the HTML source.
- **Subresource Integrity (SRI)**: Analyzes all external `<script>` and `<link>` tags to ensure they use cryptographic hashes.
- **Vulnerable Library Fingerprinting**: Detects outdated frontend frameworks (jQuery, React, Vue) using regex on script names.
- **Mixed Content**: Flags HTTP assets loaded on an HTTPS page.
- **SEO Spillage**: Checks OpenGraph/Twitter meta tags for accidental stack trace or internal IP leaks.

### 3. Red Team Offensive Scanners
- **Targeted Directory Fuzzer**: Rapidly probes for critical exposed files (`/.env`, `/.git/config`, `docker-compose.yml`) and hidden admin panels (`/admin`, `/wp-admin`).
- **Modern API Threats**: Probes for accidentally exposed GraphQL Introspection endpoints and Swagger OpenAPI documentation.
- **Subdomain Takeover Detection**: Enumerates subdomains via `crt.sh` and actively resolves their DNS records to flag **Dangling DNS** (ENOTFOUND) vulnerabilities.
- **WAF Fingerprinting**: Analyzes response headers (`cf-ray`, `x-sucuri`) to detect Cloudflare, AWS WAF, Akamai, Imperva, and Sucuri.
- **Open Port Scanner**: Uses raw Node.js sockets to aggressively probe the target IP for 10 critical service ports (e.g., FTP, SSH, MySQL, Postgres).
- **Broken Link Hijacking**: Scrapes outbound `<a>` tags and resolves their DNS. Flags dead domains that an attacker could register to hijack your traffic.
- **AI Scraper Defenses**: Analyzes `robots.txt` to determine if the site actively blocks modern LLM bots (`GPTBot`, `Anthropic-ai`).

### 4. 🔥 Active DAST Exploitation Engine
When a URL with parameters is provided (e.g., `?id=1`), Akhil WebGuard automatically injects malicious payloads to verify exploitability:
- **SQL Injection (SQLi)**: Fires SQL payloads and fingerprints the response for database syntax errors.
- **Cross-Site Scripting (XSS)**: Injects raw `<script>` tags to check for unsanitized payload reflection.
- **Directory Traversal (LFI)**: Attempts to break out of the web root to access `/etc/passwd` or `win.ini`.
- **Server-Side Request Forgery (SSRF)**: Injects the AWS Cloud Metadata IP into parameters to hunt for internal cloud credential leaks.
- **Authentication Weaknesses**: Explicitly analyzes HTML `<form>` elements for missing CSRF tokens, plaintext `GET` transmissions, and insecure `HTTP` actions.

### 5. 🧠 Google Gemini AI Intelligence
Akhil WebGuard has a Google Gemini API key hardcoded into its backend engine, unlocking real-time generative AI insights based on your specific scan results:
- **Phishing & Scam Assessment**: Evaluates the homepage copywriting for social engineering indicators.
- **Malicious JavaScript Analysis**: Extracts inline `<script>` tags and asks Gemini to evaluate them for obfuscated tracking malware or crypto-miners.
- **Attack Chain Generation**: Gemini synthesizes the discovered vulnerabilities to write a custom, step-by-step narrative of how a hacker could breach the target.
- **Interactive Chat Widget**: A sleek, floating chat interface that allows you to converse with the AI. It uses your unique scan JSON payload as context to answer specific security questions!

---

## 🚀 How to Run Locally

Akhil WebGuard is designed to be extremely lightweight and fast.

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

3. Start the WebGuard backend engine:
   ```bash
   node server.js
   ```

4. Open your browser and navigate to the dashboard:
   **[http://localhost:3000](http://localhost:3000)**

### Usage
- **For Passive Scanning**: Enter a root domain (e.g., `reactjs.org`).
- **For Active DAST Scanning**: Enter a URL containing query parameters (e.g., `http://testphp.vulnweb.com/listproducts.php?cat=1`).

---
*Disclaimer: WebGuard is built for educational purposes and authorized security auditing. Do not scan targets without explicit permission.*
