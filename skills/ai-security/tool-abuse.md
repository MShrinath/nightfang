# AI Security Methodology: Agentic Tool Abuse & Privilege Escalation

Methodologies for testing autonomous tool-use agents for privilege escalation and unintended action execution.

---

## 1. Confused Deputy & Privilege Leap
- Identify if an unprivileged user can manipulate the agent into invoking tools reserved for administrative tasks.
- Test whether the agent verifies user authorization before executing destructive tool calls.

---

## 2. Server-Side Request Forgery via Tools
- If the agent has web browsing or URL fetching tools, instruct it to retrieve internal IP addresses (`127.0.0.1`, `169.254.169.254`).
- Evaluate whether tool sandboxing enforces network egress policies.

---

## 3. Unsafe Execution Primitives
- Test if code execution tools (Python interpreter, bash runners) allow breakout from sandbox environments into the underlying host OS.
