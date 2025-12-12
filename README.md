# NETRA - Enterprise Attack Surface Management (ASM)

## 1. Product Vision
NETRA is not just a scanner; it is a **Continuous Attack Surface Management (ASM)** platform designed for modern, cloud-native enterprises.

While traditional scanners wait for you to define a target, NETRA continuously monitors your infrastructure to detect **Shadow IT**, **Zombie APIs**, and **Compliance Drifts** in real-time. Built on a scalable Kubernetes-native architecture, it scales from a single startup website to Fortune 500 infrastructure effortlessly.

---

## 2. The "NETRA Advantage" (Key Differentiators)

### 🛡️ Feature A: Automated Asset Discovery (Reconnaissance)
**The Problem**: Companies don't know what they own.
**The Solution**: Input a company name, and NETRA performs deep recursive enumeration:
*   **Certificate Transparency Logs**: Finds subdomains before they are even live.
*   **Cloud Hunter**: Scans AWS, Azure, and GCP IP ranges for assets belonging to the organization.
*   **Acquisition Mapping**: Links subsidiary companies to the main dashboard.

### ⚖️ Feature B: GRC & Compliance Engine
**The Problem**: Security teams speak "vulnerabilities"; C-Levels speak "risk."
**The Solution**: Every finding is automatically mapped to major compliance frameworks.
*   **Open S3 Bucket** → Mapped to **HIPAA §164.312(a)(1)**
*   **Weak SSL Cipher** → Mapped to **PCI-DSS Req 4.1**
**Benefit**: Generates audit-ready PDF reports instantly.

### 🧟 Feature C: "Zombie" API Detection
**The Problem**: Undocumented APIs are the easiest way to breach a company.
**The Solution**: NETRA parses client-side JavaScript bundles to extract API routes that are not in the official documentation (Shadow APIs) and tests them for **Broken Object Level Authorization (BOLA)**.

### 🔐 Feature D: Identity & Access Auditor (IAM Security)
**The Problem**: Weak sessions allow account takeovers (hijacking).
**The Solution**: A dedicated module that audits authentication flows without exploiting them:
*   **OAuth/SAML Validator**: Checks for misconfigured redirect URIs and weak token signatures.
*   **Session Strength Analysis**: Verifies entropy of session cookies and presence of `Secure`/`HttpOnly` flags.
*   **MFA Gap Analysis**: Identifies administrative portals that lack Multi-Factor Authentication.

### 📉 Feature E: Resilience & Stress Testing
**The Problem**: Denial of Service (DoS) attacks cause downtime and revenue loss.
**The Solution**: Controlled availability testing to ensure systems don't crash.
*   **Rate Limit Verification**: Safely tests if API endpoints correctly block traffic after a threshold (e.g., 100 req/min).
*   **Load Simulation**: Simulates user traffic spikes to validate auto-scaling rules in Kubernetes.
*   **Slowloris Defense Check**: Verifies web server timeouts are configured to prevent connection exhaustion.

### 🕵️ Feature F: Dark Web Threat Intelligence
**The Problem**: Attackers often buy access using stolen credentials before launching an attack.
**The Solution**: NETRA actively monitors external leak sources for corporate data.
*   **Breach Radar**: Integrates with "HaveIBeenPwned" and private leak databases to alert instantly if corporate emails appear in a data dump.
*   **Paste Site Monitor**: Scrapes sites like Pastebin and GitHub Gists for accidental leaks of API keys or internal config files.
    *   **Executive Protection**: specialized monitoring for C-suite personal emails to prevent spear-phishing campaigns.

### ⚔️ Feature G: Active Verification Engine (Safe Exploitation)
**The Problem**: Scanners alert on "potential" bugs. Engineers ignore them as false positives.
**The Solution**: NETRA performs **Safe Active Exploitation** to prove the bug exists without taking down the server.
*   **Safe RCE Check**: Instead of `rm -rf /`, it executes `echo $((55+55))` and checks if the response contains `110`. Proof of execution, zero damage.
*   **SQL Injection (Time-Based)**: Injects `WAITFOR DELAY '0:0:5'` and measures the response time deviation. If the server sleeps, the bug is real.
*   **LFI Probe**: Attempts to read benign files like `/etc/hostname` (never `/etc/shadow`) to confirm traversal vulnerabilities.
*   **Auto-Exploit Module**: Automatically chains findings (e.g., finding an exposed `.env` file -> extracting DB creds -> connecting to DB -> proving access).

### 🕸️ Feature H: Deception & Honeytraps
**The Problem**: "Sniffing" attacks (like Ettercap) are illegal in most enterprise contexts.
**The Solution**: NETRA sets "Ghost Routes" (fake admin portals, `/admin-backup`) that sit neutrally.
*   **Passive Fingerprinting**: If an attacker probes these honeypots, NETRA silently logs their IP, User-Agent, and JA3 fingerprint.
*   **Neutral Defense**: It doesn't hack back; it simply sits and waits for the attacker to make a mistake.

### 🛡️ Feature I: Client-Side Integrity Guard (Malware Detector)
**The Problem**: Server-side scanners miss attacks happening in the customer's browser (e.g., Magecart credit card skimming).
**The Solution**: NETRA scans the site's live JavaScript assets.
*   **Cryptominer Detection**: Identifies JS patterns used for illicit mining.
*   **Magecart Hunter**: Detects changes in payment form scripts that send data to unauthorized domains.

### 🧬 Feature J: Supply Chain "DNA" Sequencing
**The Problem**: Third-party libraries (like Polyfill.io) can be hijacked, turning trusted assets into malware vectors.
**The Solution**: NETRA verifies the "DNA" of every loaded library.
*   **Hash Verification**: Checks if `jquery.js` loading on your site matches the official vendor hash.
*   **Drift Detection**: Alerts immediately if a known library's code changes unexpectedly (e.g., a "supply chain" update injects a backdoor).

---

## 3. Enterprise Architecture
NETRA is designed to handle massive scale using a distributed microservices architecture.

### The Stack
*   **Orchestration**: Kubernetes (Helm Charts provided).
*   **Queue System**: Redis Streams (Distributes millions of targets to workers).
*   **Data Lake**: PostgreSQL (Persistent History) & AsyncIO Engine.
*   **Identity**: Keycloak (OIDC/SAML integration for Enterprise SSO).

### Deployment (Helm)
```bash
helm repo add netra https://charts.netra-security.io
helm install netra-platform netra/enterprise --set replicas=50
```

---

## 4. Integration Ecosystem
NETRA fits into the modern DevSecOps pipeline:
*   **Ticket Systems**: 2-way sync with Jira and ServiceNow. (A bug found in NETRA automatically creates a Jira ticket; closing the Jira ticket triggers a re-scan in NETRA).
*   **SIEM**: Forwards logs to Splunk or Datadog via webhooks.
*   **CI/CD**: Blocks Jenkins/GitLab builds if critical API vulnerabilities are found.

---

## 5. Roadmap: The Path to Series A
*   **Q1: AI-Powered Remediation**: Using LLMs to not just find the bug, but generate the specific code patch to fix it (e.g., "Here is the Nginx config to fix your missing security headers").
*   **Q2: Agentless Cloud Security**: Direct integration with AWS IAM roles to scan internal VPCs without deploying scanners.
*   **Q3: SaaS Multi-Tenancy**: Re-architecting for a SaaS model where multiple companies share the same infrastructure with strict data isolation.
