# Web Vulnerability Methodology: Server-Side Request Forgery (SSRF)

Methodologies for discovering, validating, and scoring SSRF vulnerabilities.

---

## 1. Attack Vectors & Entry Points
- Webhook registration URLs.
- Document/PDF export and conversion services from URL.
- Image import, profile picture fetchers, and URL preview generators.

---

## 2. Internal Probing Targets
- **Loopback Interfaces**:
  - `http://127.0.0.1:8080/`
  - `http://localhost:3000/`
  - `http://[::1]:80/`
- **Cloud Metadata Endpoints**:
  - AWS/GCP/Azure: `http://169.254.169.254/latest/meta-data/`
  - Container metadata: `http://169.254.170.2/v2/metadata`
- **Private Subnets**:
  - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`.

---

## 3. Blind SSRF Detection
- Submit out-of-band DNS callback domains (e.g., Interactsh / Burp Collaborator).
- Check for DNS query resolution or incoming HTTP callback connections.
- Flag blind SSRF as Medium/High severity depending on internal reach.
