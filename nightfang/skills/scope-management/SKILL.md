---
name: scope-management
description: >-
  Use this skill for engagement scope parsing, validation, and enforcement.
  Parses operator-provided scope definitions (domains, IPs, URLs, ports),
  validates targets before testing, and enforces boundaries throughout
  the engagement. Activate at engagement start and reference before
  every testing action.
---

# Scope Management

Parse, validate, and enforce engagement scope boundaries.

## Scope Input Format

Accept scope in flexible formats from the operator:

```yaml
# Example scope definition
scope:
  in_scope:
    domains:
      - "*.example.com"
      - "api.example.com"
    ips:
      - "192.168.1.0/24"
      - "10.0.0.1-10.0.0.50"
    urls:
      - "https://app.example.com/*"
      - "https://api.example.com/v2/*"
    ports:
      - "80,443,8080,8443"
      - "1-1024"  # range
  
  out_of_scope:
    domains:
      - "production.example.com"
      - "payments.example.com"
    ips:
      - "192.168.1.1"  # gateway
    urls:
      - "*/admin/delete*"
    notes:
      - "Do NOT test against production database"
      - "No denial of service testing"
  
  credentials:
    - role: "regular_user"
      username: "testuser1"
      password: "[provided]"
    - role: "admin"
      username: "admin_test"
      password: "[provided]"
  
  rules_of_engagement:
    - "Testing window: Mon-Fri 09:00-18:00 UTC"
    - "Maximum scan rate: 100 req/sec"
    - "No social engineering"
    - "No physical testing"
    - "Report critical findings immediately"
```

## Validation Functions

### Target Validation
Before ANY scan or test action:
1. Extract target host/IP from the command
2. Check against in_scope list
3. Check against out_of_scope exclusions
4. Verify port is in allowed range
5. Check if within testing window
6. If ANY check fails → BLOCK and log

### Domain Matching
- `*.example.com` matches `sub.example.com` but NOT `example.com`
- `example.com` matches exactly
- Case-insensitive matching

### IP Range Matching
- CIDR notation: `192.168.1.0/24`
- Range notation: `10.0.0.1-10.0.0.50`
- Single IP: `10.0.0.1`

## Scope Drift Detection
- Monitor discovered assets during recon
- Flag any asset that resolves outside scope
- Alert operator about adjacent interesting targets found
- Never test out-of-scope assets even if they seem related

## Procedure

1. **Parse**: Accept scope input from operator
2. **Normalize**: Convert all entries to canonical format
3. **Validate**: Verify scope makes sense (no conflicts)
4. **Confirm**: Present parsed scope back to operator for verification
5. **Enforce**: Check every action against scope throughout engagement
6. **Log**: Record any scope violations or boundary attempts

## Output
- Parsed scope summary
- Validation results
- Scope boundary map
- Any ambiguities flagged for operator clarification
