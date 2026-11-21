# Methodology: threat-modeling

Source: [PentestingEverything/Threat Modeling](https://github.com/m14r41/PentestingEverything/tree/main/Threat%20Modeling)

---



# Understanding Threat Modeling in SDLC 

Before understanding **Threat Modeling**, it is important to understand where it fits in the **Software Development Life Cycle (SDLC)** and what happens before security testing begins.

Security is not something that starts after development  i.e it starts from the very beginning of the system idea.

---

# SDLC Flow Normally (Security Point of View)

> From a product security perspective, the early phases of SDLC look like this:

| Stage               | Description                           |
| ------------------- | ------------------------------------- |
| Idea Review         | Identify early risks at concept stage |
| Design Review       | Check security in design & APIs       |
| Architecture Review | Review full system structure          |
| Threat Modeling     | Identify and simulate attacks         |
| Development         | Secure coding implementation          |
| Testing             | Find vulnerabilities in real system   |
| Deployment          | Monitor and respond to attacks        |

---

## 1. Idea Review (Requirement Stage)

Idea review is the earliest stage of SDLC where a product or feature is still just a concept. At this stage, the focus is on understanding what we are building, why we are building it, and what type of data will be used. The security goal is to identify basic risks before any design or development starts. For example, if a file upload feature is planned, we think about whether users can upload malicious files, where those files will be stored, and who will have access to them. At this stage, security thinking is only high-level and conceptual.


## 2. Design Review

Design review happens when the system design starts taking shape, including APIs, database structure, and user flows. The focus is on API structure, authentication flow, data flow between components, and external integrations. The security goal is to identify design-level flaws before coding begins. For example, missing authorization in API design can lead to IDOR risks, sensitive data may be sent without encryption, or client-side validation may be wrongly trusted. This stage is mainly about making secure design decisions before implementation.


## 3. Architecture Review

Architecture review is performed when the full system structure is defined, including frontend, backend, database, and external services. The focus is on understanding system components, trust boundaries, third-party integrations, and network com

---

