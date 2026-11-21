# Threat Emulation Skill

**Category**: Adversary Simulation / MITRE ATT&CK Mapping  
**Associated Agents**: `threat-emulator-agent`, `purple-team-operator`, `blue-team-agent`  
**Payload Integration**: Each technique maps to CWE + OWASP entries. Use `resolver.get_by_cwe(cwe_id)` for technique-specific safe payloads.

---

## 1. Scope

Systematic emulation of adversary behaviors using MITRE ATT&CK framework techniques mapped to non-destructive proof-of-concept operations. Bridges red team actions with blue team detection validation.

---

## 2. ATT&CK Technique Catalog (Safe Subsets Only)

### Initial Access (TA0001)
| ID | Name | Safe PoC | Detection Difficulty |
|----|------|----------|---------------------|
| T1566.001 | Spearphishing Attachment | Simulated email header analysis | Medium |
| T1190 | Exploit Public-Facing App | CVE-verified benign probe | High |

### Execution (TA0002)
| ID | Name | Safe PoC | Detection Difficulty |
|----|------|----------|---------------------|
| T1059.004 | PowerShell | `Get-Help` only (no cmdlet execution) | Low |
| T1059.007 | JavaScript | DOM inspection, no eval() | Low |

### Persistence (TA0003)
| ID | Name | Safe PoC | Detection Difficulty |
|----|------|----------|---------------------|
| T1547.001 | Registry Run Keys | Enumerate existing run keys | Low |
| T1053.005 | Scheduled Task | Enumerate scheduled task configuration | Low |

### Privilege Escalation (TA0004)
| ID | Name | Safe PoC | Detection Difficulty |
|----|------|----------|---------------------|
| T1548.003 | Setuid/Setgid | Binary permission audit only | Medium |
| T1068 | Exploitation for PrivEsc | CVE search + version matching | High |

### Defense Evasion (TA0005)
| ID | Name | Safe PoC | Detection Difficulty |
|----|------|----------|---------------------|
| T1070.004 | File Deletion | Archive-only (no deletion) | Low |
| T1027 | Obfuscated Files | Signature scan for known packers | Medium |

### Credential Access (TA0006)
| ID | Name | Safe PoC | Detection Difficulty |
|----|------|----------|---------------------|
| T1003.001 | LSASS Memory | Read-only process listing only | High |
| T1552.004 | Private Keys | Certificate store enumeration | Medium |

### Discovery (TA0007)
| ID | Name | Safe PoC | Detection Difficulty |
|----|------|----------|---------------------|
| T1082 | System Info | OS version query only | Very Low |
| T1069 | Permission Groups | Group membership enumeration | Low |
| T1201 | Password Policy | Policy read from registry/GPO | Low |

### Lateral Movement (TA0008)
| ID | Name | Safe PoC | Detection Difficulty |
|----|------|----------|---------------------|
| T1021.002 | SMB/Windows Admin Shares | Port probe + share listing (no access) | Medium |
| T1021.004 | SSH | Auth attempt with throwaway key | Low |

---

## 3. Campaign Generation Workflow

1. **Select Target Tier** → Determine privilege level of simulated operator account
2. **Choose Tactics** → Map campaign objectives to relevant ATT&CK tactic IDs
3. **Generate Sequence** → Order techniques by realism and dependency chains
4. **Apply Safety Filter** → Remove any technique requiring destructive action
5. **Assign Noise Profile** → QUIET/MODERATE/Loud based on detectability
6. **Output EMULATION_TASK** → Structured JSON for Daemon queue injection

---

## 4. Output Schema Compliance

Each simulated technique produces a finding with:
```yaml
finding:
  category: "emulation"
  tool_used: "mitre_attack_emulation"
  confidence.score: 10          # Always certain — this is controlled simulation
  severity.score: 0             # Not a real vulnerability — indicates detection gap
  detection_status.sigma_id: "[generated rule ID]"
  emulation.atomic_test_id: "[campaign-id]-[tech-id]"
  threat_intel.actor: ""        # Populated if technique matches known APT signature
```

---

## 5. References

- MITRE ATT&CK Enterprise Matrix: https://attack.mitre.org/matrices/enterprise/
- MITRE CALDERA Framework Reference
- CISA Unified Network Assessment Methodology
