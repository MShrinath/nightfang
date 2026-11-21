# Thick Client Pentesting Workflow

## Scope

Thick client applications include Windows executables (.exe), Java applications (.jar), .NET binaries, macOS apps (.app), and native desktop clients. This workflow covers binary analysis, static/dynamic reversing, memory manipulation, and protocol-level exploitation of the client application and its communications.

## Target Identification

Before beginning engagement, confirm scope includes:
- Binary file paths or installed application directories
- Running process names and PIDs
- Inter-process communication channels (pipes, sockets, shared memory)
- Local and remote network endpoints the client contacts

If the target is a packaged application (NSIS, Inno Setup, MSI), extract and inventory all embedded resources before analysis begins.

## Phase 1 — Reconnaissance & Inventory

Run passive enumeration to build an attack surface map without triggering defenses.

1. List all installed applications matching the target category via filesystem and registry inspection.
2. Extract version information from binary headers (PE section tables, ELF notes, JAR manifest).
3. Map all dependencies: DLL side-loading candidates, Java classpath entries, NuGet/NPM packages bundled inside.
4. Catalog inter-application communication channels: named pipes, WCF endpoints, REST APIs, local TCP/UDP listeners.
5. Query running processes for loaded modules and injected hooks using forensic artifacts only; do not execute unfamiliar payloads during this phase.

**Tools**: Strings, ldd/readelf, dotnet-dump, jar tf, procmon-style trace logging (passive mode only).

**Skill Reference**: `skills/reverse-engineering`, `skills/crypto`

## Phase 2 — Static Analysis

Perform non-executive disassembly and structural review.

1. Decompile binaries using appropriate tooling for the target architecture (dnSpy/.NET Reflector for .NET, JD-GUI/Cfr for Java, Ghidra/IDA Pro for native PE/ELF).
2. Hardcode credential search: scan strings table for `password`, `api_key`, `secret`, `connection_string` patterns; verify each candidate against runtime behavior.
3. Certificate store audit: enumerate embedded X.509 certificates, private key presence, and pinning configurations.
4. Configuration file analysis: locate and decrypt stored settings (INI, XML, JSON, config sections) including local state databases.
5. Anti-tamper and anti-debug detection survey: identify integrity checks, debugger presence probes, and obfuscation layers (VMProtect, Themida, ConfuserEx).

**Tools**: Ghidra, radare2, dnSpy, CFF Explorer, peid, detect it easy, APKTool (for UWP/MAUI).

**Skill Reference**: `skills/reverse-engineering/scripts/decompile_pe.py`, `skills/crypto/scripts/cert_parser.py`

## Phase 3 — Dynamic Analysis

Execute under controlled conditions with instrumentation enabled.

1. Launch the application in a sandboxed environment with network traffic capture enabled.
2. Monitor file system access, registry modifications, and process creation events during normal operation.
3. Intercept TLS connections using certificate pinning bypass techniques where authorized.
4. Hook inter-process communication channels to observe data-in-transit formats (serialization, encryption, signing).
5. Test input handling: provide malformed input through all exposed UI entry points, command-line arguments, and IPC handlers.

**HITL Gate Required Before**: Loading unverified third-party binaries on live targets, injecting code into running processes, or modifying application state.

**Tools**: Process Monitor, Wireshark, Fiddler/Burp Suite (local proxy), x64dbg/x32dbg, Cheat Engine, Volatility 3.

**Skill Reference**: `skills/reverse-engineering`, `skills/network`

## Phase 4 — Memory & Binary Exploitation Research

Analyze memory layout and binary protection mechanisms.

1. Assess ASLR, DEP/NX, CFG, SEHOP, and structural exception handler configurations.
2. Enumerate stack canaries and identify absence of safe exception handling chains.
3. Review buffer overflow potential through fuzzer-guided input testing on all external-facing functions.
4. Test for unsafe deserialization (Java ObjectInputStream, .NET BinaryFormatter, Python pickle equivalents).
5. Evaluate credential storage: plaintext, reversible encryption, or proper hashing with salt; test key derivation function strength.

**HITL Gate Required Before**: Crafting exploit PoCs involving arbitrary code execution, reading protected memory regions (LSASS, credential managers), or demonstrating privilege escalation beyond scope authorization.

**Tools**: Frida, Objection, Burp Suite Extension for thick clients, WinDbg, IDA Pro with scripting.

**Skill Reference**: `skills/reverse-engineering/scripts/antidebug_unhook.py`, `skills/privilege-escalation`, `skills/fuzzing-engine`

## Phase 5 — Reporting & Remediation Mapping

Document findings per the NIGHTFANG finding schema and produce actionable remediation guidance.

1. Record every finding with evidence hashes, reproduction steps, and CVSS v3.1/v4.0 vectors.
2. Map findings to MITRE ATT&CK techniques (T1056 — Input Capture, T1055 — Process Injection, T1553 — Signature Policy Modification, T1558 — Forge or Reuse Tokens).
3. Produce vendor-neutral remediation guidance including secure coding patterns and patch timelines.
4. Attach Sigma/Splunk queries for detecting the observed attack patterns in endpoint telemetry.
5. Deliver executive summary emphasizing business impact of client-side compromise.

**Skill Reference**: `skills/reporting`, `skills/remediation`, `schemas/finding.md`
