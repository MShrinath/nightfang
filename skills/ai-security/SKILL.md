---
name: ai-security
description: Adversarial AI security testing covering direct/indirect prompt injection, agentic tool abuse, MCP server audits, and RAG poisoning.
domain: cybersecurity
subdomain: ai-security
tags: [ai, llm, prompt-injection, mcp, tool-abuse, rag-poisoning, mitre-atlas]
mitre_attack: [T1190, T1059]
mitre_atlas: [AML.T0051, AML.T0054, AML.T0043, AML.T0053]
d3fend_techniques: [D3-PSA, D3-MCI, D3-EAA]
version: "2.1"
---

# AI & LLM Systems Security Skill (Index & Router)

This skill provides modular methodologies for evaluating LLM applications, agentic tools, and Model Context Protocol (MCP) servers. Load specific sub-modules as needed:

## Sub-Modules
- **Prompt Injection & Canaries**: [`prompt-injection.md`](prompt-injection.md) — Direct/indirect injection and canary reflection tests.
- **MCP Server Audits**: [`mcp-audit.md`](mcp-audit.md) — Tool definitions, schema boundary checks, and local transport security.
- **Agentic Tool Abuse**: [`tool-abuse.md`](tool-abuse.md) — Confused deputy, tool parameter escalation, and SSRF via tools.

## Output Contract
All findings must be formatted conforming to [`schemas/finding.md`](../../schemas/finding.md) mapped to **MITRE ATLAS** technique IDs.
