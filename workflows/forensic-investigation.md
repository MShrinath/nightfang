# Digital Forensics & Incident Response Workflow

## Scope

This workflow applies structured digital forensics methodologies to support incident response investigations, evidence preservation, and root cause analysis. It covers disk image acquisition, memory forensics, log analysis, network artifact examination, and timeline reconstruction. All operations follow chain-of-custody requirements defined in `references/sops.md#sop-06-evidence-hashing-chain-of-custody`. This workflow is read-only: no remediation or cleanup occurs during forensic examination.

## Prerequisites

- Legal authority or contractual right to examine target systems, media, and data stores.
- Write-blocked acquisition hardware or verified read-only mounting for all storage media under examination.
- Forensic workstation isolation from production networks to prevent cross-contamination.
- Case identification number assigned and documented before any evidence handling begins.

**Skill Reference**: `AGENTS.md` § SOP-01, `schemas/finding.md` provenance hash requirements

## Phase 1 — Evidence Acquisition & Integrity Verification

Capture forensic images preserving original media state without modification.

1. Identify all candidate evidence sources: physical disks, virtual machine snapshots, cloud volume snapshots, memory dumps, mobile device extractions, network capture files, application logs, email archives, and endpoint telemetry exports.
2. Create bit-for-bit forensic images using write-blocking hardware (Tableau, TableauForensics) or software write-blockers (FTK Imager read-only mode, dd with conv=noerror,sync). Record exact command invocations and parameters.
3. Compute SHA-256 hashes of all acquired images immediately after creation and document the values on the case evidence log sheet.
4. Verify hash consistency by recomputing and comparing against initial measurements before proceeding with any analysis operations.
5. Store原始 images on encrypted external media with access controlled by case investigator assignment only; maintain duplicate verification copies on separate physical media.

**Tools**: FTK Imager, ddrescue, Guymager, Autopsy acquisition module, HashCalc for independent verification.

**Skill Reference**: `skills/forensics/scripts/evidence_collector.py`, `schemas/finding.md`

## Phase 2 — Memory Forensics Analysis

Examine volatile system state for running processes, injected code, network connections, and credential material.

1. Acquire memory dump using established acquisition methods matching the OS (WinPmem for Windows, LiME for Linux, MacPmem for macOS). Compute hashes of the captured memory image.
2. Load memory image into Volatility 3 framework with correct profile selection matching the source operating system version and architecture.
3. Enumerate running processes, loaded driver modules, DLL/ELF mappings, and identify entries absent from standard process listings indicating potential hidden or injected code.
4. Extract network connection artifacts showing established TCP sessions, listening ports, and DNS resolver cache entries active at time of acquisition.
5. Search for credential material including LSASS memory extraction (Windows), sudo cached credentials, SSH agent sockets, browser login session cookies, and saved VPN connection profiles where legally authorized.

**HITL Gate Required Before**: Attempting credential extraction from LSASS or equivalent protected memory regions; accessing encrypted private key material stored in memory; examining user personal communication content beyond scope authorization.

**Tools**: Volatility 3, Rekall, yara-memory-scanner, LPE detection plugins, malware config extractors.

**Skill Reference**: `skills/forensics/scripts/timeline_builder.py`, `skills/hunting/scripts/beacon_hunter.py`

## Phase 3 — Disk Image & Filesystem Examination

Conduct systematic review of persistent storage for artifacts relevant to the investigation.

1. Parse filesystem structures (NTFS MFT, ext4 journal, APFS containers, HFS+ catalogs) to reconstruct deleted file recovery and identify recently accessed or modified files within investigative timeframes.
2. Extract browser artifacts: history, bookmarks, download records, form autofill data, cached credentials, extension configurations, and cookie databases across Chrome, Firefox, Edge, Safari profiles.
3. Analyze registry hives (Windows) or plist databases (macOS) for startup persistence mechanisms, USB device attachment history, WLAN profile imports, recent file execution traces (ShimCache, Amcache, LSINotes).
4. Decode archived container formats (.zip, .rar, .7z, .cab) for embedded executable payloads or configuration files that may contain malicious tooling or stolen data staging areas.
5. Review prefetch files, jump lists, shellbags, and USN journal entries to establish user activity timelines and software execution history consistent with observed compromise indicators.

**Tools**: Autopsy forensic platform, Registry Explorer, Plausible, ChromeHistoryView, ShellBagAnalyzer, dfvfs (LibVolkano forensic library).

**Skill Reference**: `skills/forensics`, `schemas/finding.md`

## Phase 4 — Network Traffic & Log Correlation

Reconstruct attacker activity patterns through packet capture analysis and centralized log examination.

1. Parse PCAP files using tshark and custom dissection scripts to identify lateral movement paths, data exfiltration volumes, DNS tunneling indicators, and known C2 protocol signatures.
2. Correlate firewall logs, proxy server access logs, and DNS query logs with endpoint EDR telemetry to establish attack timeline spanning initial access vector through objective achievement.
3. Apply YARA rules against binary artifacts found on disk images to match known malware families, builder signatures, and compiled tool variants used during the intrusion.
4. Reconstruct HTTP/HTTPS session flows from extracted certificates and decrypted traffic where keys are available; catalog all uploaded and downloaded resources.
5. Build event correlation queries identifying anomalous time-window clustering of authentication failures followed by successful logins from unusual source geolocations.

**Tools**: Wireshark/tshark, NetworkMiner, Xplico, ELK Stack/Loki for log correlation, YARA rule engine, custom PyPcap analysis scripts.

**Skill Reference**: `skills/forensics/scripts/pcap_analyzer.py`, `skills/hunting/scripts/ioc_extractor.py`, `workflows/osint-collection.md`

## Phase 5 — Timeline Reconstruction & Reporting

Produce a comprehensive forensic report documenting findings, methodology, and evidentiary conclusions.

1. Generate unified chronological timeline merging events from memory artifacts, disk timestamps, network captures, and authentication logs into a single investigation narrative ordered by UTC timestamp.
2. Document every piece of evidence examined with acquisition method, hash verification status, examiner name, date/time of examination, and tools used — satisfying Daubert/Frye admissibility standards where applicable.
3. Distinguish between confirmed findings (directly observed evidence), inferred conclusions (logical deduction from corroborating indicators), and speculative observations (hypotheses requiring further investigation).
4. Assign severity classifications per `schemas/finding.md` dual ranking system for each significant finding; compute CVSS v3.1/v4.0 vectors where applicable to vulnerability-driven root causes.
5. Deliver actionable IOCs package suitable for organization-wide threat hunting deployment and provide remediation prioritization guidance to the incident response team lead.

**Skill Reference**: `skills/reporting/scripts/report_assembler.py`, `templates/master_report.md`, `integration/execution-policy-gateway.md`
