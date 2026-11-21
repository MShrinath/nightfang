# Methodology: phishing

Source: [PentestingEverything/Phishing Assessment](https://github.com/m14r41/PentestingEverything/tree/main/Phishing%20Assessment)

---

## Phishing Penetration Testing Checklist

## Core Concepts

A phishing assessment is an authorized social engineering exercise that measures how susceptible an organization's people and email controls are to deceptive messages designed to steal credentials, deliver payloads, or trigger risky actions. The goal is to quantify human risk and validate technical defenses (email filtering, MFA, awareness), not to harm staff.

**Phases**
- Scope and rules of engagement: agree on targets, pretexts, timing, and reporting boundaries with the client.
- Reconnaissance: gather public emails, names, roles, and tech stack to craft believable lures.
- Infrastructure setup: register look-alike domains, configure sending infrastructure, and build landing pages.
- Campaign execution: send pretext emails and capture clicks, submitted credentials, and payload execution.
- Measurement and reporting: track click and report rates, then deliver findings and awareness recommendations.

**What to look for**
- Click-through, credential-submission, and "report phishing" rates across the user base.
- Whether MFA, conditional access, or proxy controls stop a captured credential.
- Email authentication gaps (SPF, DKIM, DMARC) that allow spoofing of trusted domains.
- High-risk groups or individuals (finance, executives, IT) needing targeted training.
- Detection and response time: did security tooling or the SOC catch the campaign.

- [ ] **Reconnaissance and Information Gathering:**
   - **Tools:** 
     - [OSINT Framework](https://osintframework.com/)
     - [Shodan](https://www.shodan.io/)
     - WHOIS lookup.
   - **Commands:** 
     - WHOIS Lookup: `whois target.com`

- [ ] **Phishing Payload Creation:**
   - **Tools:** 
     - [GoPhish](https://getgophish.com/)
     - [Social-Engineer Toolkit (SET)](https://github.com/trustedsec/social-engineer-toolkit).
   - **Commands:** 
     - Start GoPhish: `gophish`
     - Launch SET: `setoolkit`

- [ ] **Email Spoofing and Crafting:**
   - **Tools:** Email spoofing tools, email client.
   - **Commands:** 
     - Use your preferred email client to craft and send phishing emails.

- [ ] **Domain Spoofing:**
   - **Tools:** Domain registration services.
   - **Commands:** 
     - Register domains similar to the target organization's domain.

- [ ] **Sending Phishing Emails:**
   - **Tools:** 
     - [GoPhish](https://getgophish.com/)
     - [SET](https://github.com/trustedsec/social-engineer-toolkit)
     - SMTP servers.
   - **Commands:** 
  

---

