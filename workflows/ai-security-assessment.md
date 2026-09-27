# AI Security Assessment Workflow

**Workflow ID**: `ai-security-assessment`  
**Description**: Specialized offensive security testing workflow targeting LLM applications, agentic tool workflows, Model Context Protocol (MCP) servers, and RAG pipelines.  
**Required Agents**: `ai-security`, `validation`, `reporter`  
**Finding Schema**: [`schemas/finding.md`](../schemas/finding.md)  

---

## Workflow Lifecycle

1. **Intake & Threat Modeling**:
   - Identify model endpoints, agent system instructions, registered tools, and MCP servers.
   - Define test canaries and boundaries (e.g., test databases, isolated sandbox tools).
2. **Direct Prompt Injection Probing (`ai-security`)**:
   - System prompt leakage tests.
   - Safety guardrail bypass and persona hijacking.
   - Evaluation with deterministic canary reflection.
3. **Indirect Prompt Injection Probing (`ai-security`)**:
   - Inject adversarial payloads into test documents, database records, and mock external search results.
   - Observe if the agent executes malicious actions during document processing or summarization.
4. **Tool Use & MCP Server Auditing (`ai-security`)**:
   - Test parameter boundaries on high-risk tools (file system, SQL, shell execution).
   - Audit MCP schemas for unauthenticated access or excessive permissions.
5. **HITL Gate**: Present prompt overrides and tool escalation candidates to operator for verification.
6. **PoC Verification (`validation`)**: Capture proof transcripts and evaluate blast radius in isolated sandbox.
7. **Reporting & Mitigation Mapping (`reporter`)**:
   - Map vulnerabilities to **MITRE ATLAS** (`AML.T0054`, `AML.T0051`, `AML.T0043`) and **OWASP LLM Top 10**.
   - Recommend defensive countermeasures (`D3-MCI` Model Context Isolation, `D3-PSA` Parameter Sanitization).
