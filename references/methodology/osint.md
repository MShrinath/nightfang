# Methodology: osint

Source: [PentestingEverything/OSINT](https://github.com/m14r41/PentestingEverything/tree/main/OSINT)

---

# OSINT Collections and tools || Check Lists

<p align="center">
  <a href="https://web-check.xyz/" target="_blank">
    <img src="https://github.com/m14r41/PENTESTING/assets/95265573/b5ae4791-8b7f-4530-8c35-c2f74262f2ae" alt="Image" width="90%" height="550" />
  </a>
</p>

![image](https://github.com/user-attachments/assets/1ce186f2-2967-443c-87a9-123afba73b3b)


## Core Concepts

OSINT (Open Source Intelligence) is the practice of collecting and analyzing publicly available information about a target (organization, domain, person, or asset) without touching the target directly. The goal is to map the attack surface and human footprint that an adversary could exploit, before any active testing begins.

**Methodology**
- Scope and seed data: confirm authorized targets and gather starting points (company name, domains, key people, brands).
- Passive collection: search engines, social media, public records, and metadata, leaving no trace on the target.
- Infrastructure and footprint mapping: domains, subdomains, IP ranges, exposed services, certificates, and cloud assets.
- People and credential exposure: employees, emails, usernames, roles, and breach/leak data tied to the org.
- Leak and code search: paste sites, public repos, and document metadata for secrets or sensitive disclosure.
- Triage and report: validate findings, remove noise, and prioritize what feeds the active assessment.

**What to look for**
- Externally exposed hosts, forgotten subdomains, and shadow IT not in official inventory.
- Leaked credentials, API keys, and tokens in breaches, pastes, and source code.
- Employee details usable for phishing or social engineering (emails, titles, tech stack hints).
- Sensitive metadata in public documents (usernames, software versions, internal paths).
- Misconfigured or public cloud storage and services tied to the organization.

| Site                                                            | Description                                                                                                                                      |
| --------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| [WebCheck](https://web-check.xyz/)                              | An all-in-one tool for discovering information about a website or host.                                                              

---

