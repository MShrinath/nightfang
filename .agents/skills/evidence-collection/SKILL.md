---
name: evidence-collection
description: >-
  Use this skill for collecting, organizing, and preserving evidence
  during penetration testing. Captures command outputs, HTTP
  request/response pairs, tool results, and timestamps. Maintains
  chain of custody for findings. Activate alongside every testing
  skill to document evidence.
---

# Evidence Collection & Preservation

Systematic evidence gathering for findings documentation.

## Evidence Types

### 1. Command Evidence
```yaml
evidence:
  type: "command"
  timestamp: "2024-01-15T10:30:00Z"
  tool: "nmap"
  command: "nmap -sV -sC -p 80,443 target.com"
  output: |
    [full command output]
  finding_id: "NIGHTFANG-001"
  agent: "recon-active"
```

### 2. HTTP Evidence
```yaml
evidence:
  type: "http"
  timestamp: "2024-01-15T11:00:00Z"
  request: |
    POST /api/users HTTP/1.1
    Host: target.com
    Content-Type: application/json
    Authorization: Bearer eyJ...
    
    {"id": "../../etc/passwd"}
  response: |
    HTTP/1.1 200 OK
    Content-Type: text/plain
    
    root:x:0:0:root:/root:/bin/bash
    ...
  finding_id: "NIGHTFANG-005"
```

### 3. Screenshot Evidence
```yaml
evidence:
  type: "screenshot"
  timestamp: "2024-01-15T11:30:00Z"
  description: "Admin panel accessible without authentication"
  file_path: "evidence/screenshots/admin_panel_unauth.png"
  finding_id: "NIGHTFANG-008"
```

### 4. File Evidence
```yaml
evidence:
  type: "file"
  timestamp: "2024-01-15T12:00:00Z"
  description: "Extracted configuration file containing credentials"
  file_path: "evidence/files/config.xml"
  hash_sha256: "abc123..."
  finding_id: "NIGHTFANG-012"
```

## Evidence Organization

```
evidence/
├── engagement_[date]/
│   ├── recon/
│   │   ├── passive/
│   │   └── active/
│   ├── scanning/
│   ├── exploitation/
│   ├── post_exploitation/
│   ├── screenshots/
│   ├── files/
│   └── logs/
│       ├── commands.log
│       ├── http_traffic.log
│       └── timeline.log
```

## Best Practices

1. **Timestamp everything**: UTC timestamps on all evidence
2. **Hash files**: SHA256 hash of any extracted files
3. **Full capture**: Save complete request/response, not just relevant parts
4. **Context notes**: Brief explanation of why this evidence matters
5. **Link to findings**: Every piece of evidence must reference a finding ID
6. **No modification**: Evidence should be raw, unmodified output
7. **Secure storage**: Sensitive evidence must be handled carefully

## Chain of Custody
- Log who (which agent) collected each piece of evidence
- Record when it was collected
- Track any transformations applied
- Maintain integrity hashes
