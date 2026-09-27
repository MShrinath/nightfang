# AI Security Methodology: Model Context Protocol (MCP) Auditing

Methodologies for evaluating MCP servers, tool definitions, dynamic resources, and local protocol boundaries.

---

## 1. Tool Definition & Schema Auditing
- **Excessive Permissions**: Identify tools declared with overbroad capabilities (e.g., executing arbitrary bash commands, unrestricted SQL queries, arbitrary filesystem writes).
- **Parameter Validation**: Evaluate whether MCP tool implementations sanitize input arguments against shell metacharacters and directory traversal sequences.

---

## 2. Resource & Prompt Injection
- **Dynamic Resource Poisoning**: Inspect if MCP resources (`resource://`) reflect untrusted data into host context without clear boundary delimiters.
- **Prompt Template Abuse**: Test if prompt arguments can break out of template structures to hijack orchestrator instructions.

---

## 3. Transport & Authentication
- **Local RPC Exposure**: Test if local SSE or stdio transports enforce authentication or allow unauthorized processes on the host to invoke MCP methods.
