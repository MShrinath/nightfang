# Reverse Engineering & Binary Assessment Workflow

**Workflow ID**: `reverse-engineering`  
**Description**: Systematic binary, firmware, and protocol analysis workflow for vulnerability research, malware dissection, and proprietary protocol inspection.  
**Required Agents**: `reverse-engineer`, `malware-analyst`, `code-auditor`, `reporter`  
**Finding Schema**: [`schemas/finding.md`](../schemas/finding.md)  

---

## Workflow Lifecycle

1. **Phase 1 — Artifact Ingestion & Triage (`malware-analyst`, `reverse-engineer`)**:
   - Compute cryptographic hashes (SHA-256), examine file headers, inspect entropy, and determine compiler/architecture specifications.
2. **Phase 2 — Static Disassembly & Decompilation (`reverse-engineer`)**:
   - Disassemble executable using headless decompilers (Ghidra, Radare2).
   - Reconstruct Control Flow Graphs (CFG), cross-references (XREFs), and import/export address tables.
3. **Phase 3 — Cryptographic & Hardcoded Secret Extraction (`reverse-engineer`)**:
   - Identify embedded encryption keys, proprietary tokens, initialization vectors, and hidden backend URLs.
4. **Phase 4 — Sink Reachability & Vulnerability Mapping (`reverse-engineer`, `code-auditor`)**:
   - Trace untrusted input paths to critical sinks (memory copy buffers, format string functions, system command execution).
   - Run variant analysis (`cve_diff.py`) against known vulnerability patterns.
5. **Phase 5 — Isolated Dynamic Emulation & Instrumentation (`reverse-engineer`)**:
   - Execute binary logic inside an air-gapped container sandbox with API hooking (Frida/QEMU) to observe runtime behavior.
6. **Phase 6 — Detection Signature Authoring (`malware-analyst`)**:
   - Author YARA rules and endpoint telemetry signatures targeting unique byte patterns and behavioral characteristics.
7. **Phase 7 — Technical Reporting (`reporter`)**:
   - Compile comprehensive reverse engineering report including function call trees, extracted indicators, and remediation advice.
