# 🛠️ NIGHTFANG — Tool Inventory & Fallback Matrix

This document defines all external security tools utilized across the NIGHTFANG swarm, including standard command lines, timeouts, safety flags, and fallback alternatives.

---

## 1. Reconnaissance & OSINT Tools

| Tool | Purpose | Standard Execution Command | Timeout | Fallback Alternative |
| :--- | :--- | :--- | :--- | :--- |
| `subfinder` | Passive subdomain enum | `subfinder -d <DOMAIN> -silent` | 5m | `amass enum -passive` |
| `amass` | OSINT network mapping | `amass enum -passive -d <DOMAIN>` | 10m | `crt.sh API curl` |
| `whois` | Registration data | `whois <DOMAIN>` | 30s | `dnsrecon` |
| `dig` / `nslookup`| DNS record discovery | `dig <DOMAIN> ANY +noall +answer` | 30s | Python `dnspython` |
| `whatweb` | Tech stack identification | `whatweb -a 1 <TARGET>` | 2m | `wappalyzer-cli` / curl headers |
| `wafw00f` | WAF detection | `wafw00f <TARGET>` | 1m | Response header heuristics |

---

## 2. Active Network Scanning & Service Fingerprinting

| Tool | Purpose | Standard Execution Command | Timeout | Fallback Alternative |
| :--- | :--- | :--- | :--- | :--- |
| `nmap` | Port & service scan | `nmap -sS -T4 -p- --min-rate 1000 <TARGET>` | 30m | `masscan` / `rustscan` |
| `masscan` | High-rate subnet scanning | `masscan -p1-65535 <TARGET> --rate=1000` | 15m | `rustscan -a <TARGET>` |
| `enum4linux` | SMB/NetBIOS enum | `enum4linux -a <TARGET>` | 5m | `crackmapexec smb` |
| `testssl.sh` | TLS cipher & cert audit | `testssl.sh --quiet --color 0 <TARGET>:443` | 5m | `sslscan` / `sslyze` |

---

## 3. Web & API Application Security Tools

| Tool | Purpose | Standard Execution Command | Timeout | Fallback Alternative |
| :--- | :--- | :--- | :--- | :--- |
| `nuclei` | Template vuln scanner | `nuclei -u <TARGET> -tags cve,misconfig -silent`| 15m | `nikto -h <TARGET>` |
| `ffuf` | Web directory & param fuzzing | `ffuf -u <URL>/FUZZ -w <WORDLIST> -mc 200,301,302`| 10m | `gobuster dir` / `katana` |
| `katana` | Next-gen web crawler | `katana -u <TARGET> -d 3 -silent` | 10m | `gospider` |
| `arjun` | Hidden parameter miner | `arjun -u <URL> -m GET,POST` | 5m | `paramspider` |
| `graphql-cop`| GraphQL security auditor | `graphql-cop -t <ENDPOINT>` | 3m | `InQL` extension |
| `dalfox` | XSS vulnerability scanner | `dalfox url <TARGET> --silence` | 5m | Manual PoC |

---

## 4. Threat Hunting & Exploitation Tools (Strict HITL Required)

| Tool | Purpose | Standard Execution Command | Safety / Fallback |
| :--- | :--- | :--- | :--- |
| `sqlmap` | SQL injection PoC | `sqlmap -u "<URL>" --batch --dbs` | ⚠️ **HITL Required**. No `--os-shell` without `/go`. |
| `commix` | Command injection PoC | `commix --url "<URL>" --batch` | ⚠️ **HITL Required**. Single benign command only. |
| `crackmapexec`| Credential validation | `crackmapexec smb <TARGET> -u <USERS> -p <PASS>` | ⚠️ **HITL Required**. Respect lockout thresholds. |
| `hydra` | Controlled login spray | `hydra -L <USERLIST> -P <PASSLIST> <TARGET> <SVC>`| ⚠️ **HITL Required**. Max 3 attempts per user. |

---

## 5. Cloud & AI / LLM Testing Tools

| Tool | Purpose | Standard Execution Command |
| :--- | :--- | :--- |
| `ScoutSuite` | Multi-cloud security audit | `scout aws --no-browser` |
| `Prowler` | AWS CIS benchmark audit | `prowler aws` |
| `curl` / `requests`| Adversarial LLM prompt testing | Python script with timeout & session isolation |
| `Playwright` / `Puppeteer`| Dynamic SPA DOM inspection & screenshots | MCP Server headless browser engine |
