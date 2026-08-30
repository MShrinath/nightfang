---
name: memory-management
description: >-
  Use this skill for engagement memory and context management. Tracks
  scope definitions, discovered assets, findings, operator decisions,
  engagement timeline, and cross-phase correlations. Ensures continuity
  across swarm agents and prevents redundant work. Activate at the
  start of every engagement and maintain throughout.
---

# Engagement Memory Management

Maintain persistent context and state across the engagement lifecycle.

## Memory Stores

### 1. Scope Registry
```yaml
scope:
  domains: []
  ip_ranges: []
  urls: []
  ports: []
  excluded: []
  credentials_provided: []
  rules_of_engagement: ""
  start_date: ""
  end_date: ""
```

### 2. Asset Inventory
```yaml
assets:
  - host: ""
    ip: ""
    ports: []
    services: []
    os: ""
    technologies: []
    notes: ""
    status: "discovered|scanned|tested|exploited"
```

### 3. Findings Log
```yaml
findings:
  - id: "HERMES-001"
    title: ""
    target: ""
    type: ""
    confidence: 0
    severity: 0
    status: "suspected|confirmed|exploited|false_positive"
    evidence: ""
    operator_decision: "pending|approved|denied"
    reproduction_steps: []
    remediation: ""
    discovered_by: "agent_name"
    timestamp: ""
```

### 4. Decision Log
```yaml
decisions:
  - timestamp: ""
    finding_id: ""
    action_requested: ""
    operator_response: "go|hold|stop"
    notes: ""
```

### 5. Engagement Timeline
```yaml
timeline:
  - timestamp: ""
    phase: "recon|scan|exploit|post-exploit|report"
    agent: ""
    action: ""
    result: ""
    finding_ids: []
```

## Memory Operations

### Write
- After every significant action, update the relevant memory store
- Log all operator decisions immediately
- Track phase transitions

### Read
- Before starting any phase, review scope and existing findings
- Check decision log before attempting exploitation
- Cross-reference asset inventory to avoid duplicate scanning

### Correlate
- Link findings across phases (recon discovery → scan confirmation → exploitation)
- Build attack chains from individual findings
- Track lateral movement paths

### Deduplicate
- Merge duplicate findings from different agents/tools
- Consolidate asset entries with new information
- Unify naming conventions

## Context Sharing Between Agents

When delegating to swarm agents:
1. Share relevant scope subset
2. Share relevant asset inventory
3. Share existing findings for the target
4. Share operator decisions/preferences
5. Receive and merge results back into main memory

## Persistence
- Save memory state after each phase completion
- Enable resume capability if engagement is interrupted
- Maintain audit trail for all changes
