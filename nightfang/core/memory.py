"""Engagement memory and state management."""
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field, asdict
from threading import Lock


@dataclass
class Finding:
    id: str
    title: str
    target: str
    type: str
    confidence: int
    severity: int
    status: str = "suspected"  # suspected|confirmed|exploited|false_positive
    evidence: str = ""
    operator_decision: str = "pending"  # pending|approved|denied
    reproduction_steps: List[str] = field(default_factory=list)
    remediation: str = ""
    discovered_by: str = ""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    mitre_attack: List[str] = field(default_factory=list)
    mitre_atlas: List[str] = field(default_factory=list)
    d3fend: List[str] = field(default_factory=list)
    cve: List[str] = field(default_factory=list)
    cwe: str = ""
    cvss: str = ""
    # Runtime fields for HITL
    proposed_action: str = ""
    risk: str = ""
    description: str = ""


@dataclass
class Asset:
    host: str
    ip: str = ""
    ports: List[int] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    os: str = ""
    technologies: List[str] = field(default_factory=list)
    notes: str = ""
    status: str = "discovered"  # discovered|scanned|tested|exploited


@dataclass
class Decision:
    timestamp: str
    finding_id: str
    action_requested: str
    operator_response: str  # go|hold|stop
    notes: str = ""


@dataclass
class TimelineEvent:
    timestamp: str
    phase: str
    agent: str
    action: str
    result: str
    finding_ids: List[str] = field(default_factory=list)


@dataclass
class AttackChain:
    id: str
    name: str
    priority: str
    score: float
    steps: List[Dict]
    mitre_path: List[str]
    d3fend_counters: List[str]
    business_impact: str = ""
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict:
        return asdict(self)


class MemoryManager:
    """Manages persistent engagement memory across all phases and agents."""

    def __init__(self, engagement_dir: Path):
        self.engagement_dir = Path(engagement_dir)
        self.memory_dir = self.engagement_dir / "memory"
        self.evidence_dir = self.engagement_dir / "evidence"
        self.logs_dir = self.engagement_dir / "logs"
        self._lock = Lock()
        self._ensure_dirs()
        self._init_files()

    def _ensure_dirs(self):
        for d in [self.memory_dir, self.evidence_dir, self.logs_dir]:
            d.mkdir(parents=True, exist_ok=True)

        # Evidence subdirs
        for sub in ['recon', 'scanning', 'exploitation', 'post_exploitation', 'screenshots', 'files']:
            (self.evidence_dir / sub).mkdir(exist_ok=True)

    def _init_files(self):
        """Initialize memory files if they don't exist."""
        files = {
            'scope.json': {},
            'assets.json': [],
            'findings.json': [],
            'decisions.json': [],
            'timeline.json': [],
            'attack_chains.json': []
        }
        for fname, default in files.items():
            fpath = self.memory_dir / fname
            if not fpath.exists():
                self._write_json(fpath, default)

    def _read_json(self, path: Path) -> Any:
        with self._lock:
            with open(path) as f:
                return json.load(f)

    def _write_json(self, path: Path, data: Any):
        with self._lock:
            tmp = path.with_suffix('.tmp')
            with open(tmp, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            tmp.replace(path)

    # Scope
    def save_scope(self, scope: Dict):
        self._write_json(self.memory_dir / 'scope.json', scope)

    def load_scope(self) -> Dict:
        return self._read_json(self.memory_dir / 'scope.json')

    # Assets
    def add_asset(self, asset: Asset):
        assets = self.load_assets()
        # Deduplicate by host+ip
        for i, a in enumerate(assets):
            if a.get('host') == asset.host and a.get('ip') == asset.ip:
                assets[i] = {**a, **asdict(asset)}
                self._write_json(self.memory_dir / 'assets.json', assets)
                return
        assets.append(asdict(asset))
        self._write_json(self.memory_dir / 'assets.json', assets)

    def load_assets(self) -> List[Dict]:
        return self._read_json(self.memory_dir / 'assets.json')

    def get_asset(self, host: str, ip: str = "") -> Optional[Dict]:
        for a in self.load_assets():
            if a.get('host') == host and (not ip or a.get('ip') == ip):
                return a
        return None

    def update_asset_status(self, host: str, ip: str, status: str):
        assets = self.load_assets()
        for a in assets:
            if a.get('host') == host and a.get('ip') == ip:
                a['status'] = status
                self._write_json(self.memory_dir / 'assets.json', assets)
                return

    # Findings
    def add_finding(self, finding: Finding):
        findings = self.load_findings()
        # Check for duplicate (same target + type)
        for i, f in enumerate(findings):
            if f.get('target') == finding.target and f.get('type') == finding.type:
                # Update existing with higher confidence/severity
                if finding.confidence > f.get('confidence', 0):
                    findings[i] = asdict(finding)
                    self._write_json(self.memory_dir / 'findings.json', findings)
                    return
                return  # Existing is better or equal
        findings.append(asdict(finding))
        self._write_json(self.memory_dir / 'findings.json', findings)

    def load_findings(self) -> List[Dict]:
        return self._read_json(self.memory_dir / 'findings.json')

    def get_finding(self, finding_id: str) -> Optional[Dict]:
        for f in self.load_findings():
            if f.get('id') == finding_id:
                return f
        return None

    def update_finding(self, finding_id: str, **updates):
        findings = self.load_findings()
        for i, f in enumerate(findings):
            if f.get('id') == finding_id:
                findings[i].update(updates)
                self._write_json(self.memory_dir / 'findings.json', findings)
                return

    def get_findings_by_status(self, status: str) -> List[Dict]:
        return [f for f in self.load_findings() if f.get('status') == status]

    def get_findings_pending_approval(self) -> List[Dict]:
        return [f for f in self.load_findings() if f.get('operator_decision') == 'pending']

    # Decisions
    def log_decision(self, decision: Decision):
        decisions = self.load_decisions()
        decisions.append(asdict(decision))
        self._write_json(self.memory_dir / 'decisions.json', decisions)

    def load_decisions(self) -> List[Dict]:
        return self._read_json(self.memory_dir / 'decisions.json')

    def get_decision(self, finding_id: str) -> Optional[Dict]:
        for d in reversed(self.load_decisions()):
            if d.get('finding_id') == finding_id:
                return d
        return None

    # Timeline
    def log_event(self, event: TimelineEvent):
        timeline = self.load_timeline()
        timeline.append(asdict(event))
        self._write_json(self.memory_dir / 'timeline.json', timeline)

    def load_timeline(self) -> List[Dict]:
        return self._read_json(self.memory_dir / 'timeline.json')

    # Attack Chains
    def save_chains(self, chains: List[Dict]):
        self._write_json(self.memory_dir / 'attack_chains.json', chains)

    def load_chains(self) -> List[Dict]:
        return self._read_json(self.memory_dir / 'attack_chains.json')

    # Evidence
    def save_evidence(self, finding_id: str, evidence_type: str, content: str, metadata: Optional[Dict] = None) -> str:
        """Save evidence and return the file path."""
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        fname = f"{finding_id}_{evidence_type}_{timestamp}.txt"
        fpath = self.evidence_dir / evidence_type / fname

        with open(fpath, 'w') as f:
            f.write(content)

        # Log evidence reference
        evidence_log = self.evidence_dir / 'evidence_index.json'
        index = []
        if evidence_log.exists():
            index = self._read_json(evidence_log)
        index.append({
            'finding_id': finding_id,
            'type': evidence_type,
            'file': str(fpath.relative_to(self.engagement_dir)),
            'timestamp': datetime.utcnow().isoformat(),
            'metadata': metadata or {}
        })
        self._write_json(evidence_log, index)

        return str(fpath.relative_to(self.engagement_dir))

    def get_evidence_for_finding(self, finding_id: str) -> List[Dict]:
        evidence_log = self.evidence_dir / 'evidence_index.json'
        if not evidence_log.exists():
            return []
        index = self._read_json(evidence_log)
        return [e for e in index if e.get('finding_id') == finding_id]

    # Full state dump for resume
    def dump_state(self) -> Dict:
        return {
            'scope': self.load_scope(),
            'assets': self.load_assets(),
            'findings': self.load_findings(),
            'decisions': self.load_decisions(),
            'timeline': self.load_timeline(),
            'attack_chains': self.load_chains()
        }

    def load_state(self, state: Dict):
        if 'scope' in state: self.save_scope(state['scope'])
        if 'assets' in state: self._write_json(self.memory_dir / 'assets.json', state['assets'])
        if 'findings' in state: self._write_json(self.memory_dir / 'findings.json', state['findings'])
        if 'decisions' in state: self._write_json(self.memory_dir / 'decisions.json', state['decisions'])
        if 'timeline' in state: self._write_json(self.memory_dir / 'timeline.json', state['timeline'])
        if 'attack_chains' in state: self._write_json(self.memory_dir / 'attack_chains.json', state['attack_chains'])

    def save_phase_result(self, phase: str, result: Dict):
        """Save phase result to memory."""
        phase_file = self.memory_dir / f'phase_{phase}.json'
        self._write_json(phase_file, result)

    def load_phase_result(self, phase: str) -> Dict:
        """Load phase result from memory."""
        phase_file = self.memory_dir / f'phase_{phase}.json'
        if phase_file.exists():
            return self._read_json(phase_file)
        return {}