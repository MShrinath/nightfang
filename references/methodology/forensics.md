# Methodology: forensics

Source: [PentestingEverything/Forensic](https://github.com/m14r41/PentestingEverything/tree/main/Forensic)

---


## Core Concepts

Digital forensics (DFIR) is the disciplined collection, preservation, and analysis of digital evidence from systems, storage, mobile devices, and networks to reconstruct what happened during an incident or investigation. The goal is to produce accurate, defensible findings that hold up technically and, where needed, legally.

**Workflow**
- Identification: locate relevant systems, data sources, and evidence.
- Acquisition: capture data in a sound manner, prioritizing the most volatile sources first.
- Preservation: protect originals from alteration and maintain documentation.
- Analysis: examine artifacts, build a timeline, and correlate findings to answer the investigative questions.
- Reporting: present conclusions clearly with supporting evidence and methodology.

**Key principles**
- Order of volatility: capture memory and live state before powering down, then disk and other persistent media.
- Write-blocking and forensic imaging: work from bit-for-bit copies, never the original evidence.
- Hashing for integrity: compute and verify hashes (MD5/SHA-256) to prove evidence is unchanged.
- Chain of custody: document who handled evidence, when, and how, end to end.
- Timeline analysis: correlate timestamps across artifacts to reconstruct the sequence of events.

## Tools used for Job 

**Job Role : Digital Forensics**

 Knowledge of Forensic Tools :
>  Encase, FTK, X-Ways, Intella, Magnet Axiom, Forensic Explorer, Oxygen Forensic, UFED, Passware Password Recovery Tool,



---

## Sub-Topics

- Mobile
- Windows

