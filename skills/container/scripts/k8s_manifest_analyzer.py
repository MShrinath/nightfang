#!/usr/bin/env python3
"""
Container & Kubernetes Security Checker
Validates container images and K8s manifests for common misconfigurations.
Read-only analysis — does not modify any cluster state.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import yaml
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional


@dataclass
class ContainerFinding:
    rule_id: str
    severity: str
    title: str
    description: str
    resource_type: str  # image, pod, deployment, service, etc.
    resource_name: str
    evidence: str
    remediation: str
    cwe: str = ""
    mitre_attack: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "description": self.description[:300],
            "resource_type": self.resource_type,
            "resource_name": self.resource_name,
            "evidence": self.evidence[:400],
            "remediation": self.remediation,
            "cwe": self.cwe,
            "mitre_attacks": self.mitre_attack,
        }


@dataclass
class ContainerReport:
    target: str
    timestamp: str
    findings: List[ContainerFinding] = field(default_factory=list)
    resources_checked: int = 0

    def add(self, f: ContainerFinding) -> None:
        self.findings.append(f)
        self.resources_checked += 1

    def to_json(self, indent: int = 2) -> str:
        return json.dumps({
            "target": self.target,
            "timestamp": self.timestamp,
            "findings_count": len(self.findings),
            "resources_checked": self.resources_checked,
            "findings": [f.to_dict() for f in self.findings],
        }, indent=indent, default=str)


# ---------------------------------------------------------------------------
# Validation rules — each function is independent and composable
# ---------------------------------------------------------------------------

def check_run_as_root(spec: dict, kind: str, name: str) -> List[ContainerFinding]:
    """Detect containers running as root user."""
    findings: List[ContainerFinding] = []
    containers = spec.get("spec", {}).get("containers", []) or []
    init_containers = spec.get("spec", {}).get("initContainers", []) or []
    all_containers = [{"name": c.get("name", "unknown"), **c} for c in containers + init_containers]

    for container in all_containers:
        run_as = container.get("securityContext", {}) or {}
        run_as_user = run_as.get("runAsUser")
        run_as_nonroot = run_as.get("runAsNonRoot")

        # Explicitly running as root (UID 0)
        if run_as_user == 0:
            findings.append(ContainerFinding(
                rule_id="K8S-RUN-01",
                severity="high",
                title="Container running as root (UID 0)",
                description=f"Container '{container['name']}' in {kind}/{name} explicitly sets runAsUser: 0.",
                resource_type=kind,
                resource_name=name,
                evidence=f"runAsUser: 0",
                remediation="Set runAsNonRoot: true and assign a non-zero runAsUser (e.g., 1000).",
                cwe="CWE-250",
                mitre_attack=["TA0004"],
            ))
        elif run_as_user is None and not run_as_nonroot:
            findings.append(ContainerFinding(
                rule_id="K8S-RUN-02",
                severity="medium",
                title="No explicit non-root enforcement",
                description=f"Container '{container['name']}' in {kind}/{name} lacks runAsNonRoot: true.",
                resource_type=kind,
                resource_name=name,
                evidence="Missing securityContext.runAsNonRoot",
                remediation="Add runAsNonRoot: true to container securityContext.",
                cwe="CWE-250",
            ))
    return findings


def check_privileged_mode(spec: dict, kind: str, name: str) -> List[ContainerFinding]:
    """Detect privileged containers that can escape the container runtime."""
    findings: List[ContainerFinding] = []
    containers = spec.get("spec", {}).get("containers", []) or []
    for container in containers:
        sc = container.get("securityContext", {}) or {}
        if sc.get("privileged") is True:
            findings.append(ContainerFinding(
                rule_id="K8S-PRIV-01",
                severity="critical",
                title="Privileged container detected",
                description=f"Container '{container['name']}' in {kind}/{name} runs in privileged mode.",
                resource_type=kind,
                resource_name=name,
                evidence="securityContext.privileged: true",
                remediation="Remove privileged: true. Use specific capabilities via securityContext.capabilities.add instead.",
                cwe="CWE-250",
                mitre_attack=["TA0004", "TA0005"],
            ))
    return findings


def check_host_namespace(spec: dict, kind: str, name: str) -> List[ContainerFinding]:
    """Detect pods sharing host network, PID, or IPC namespaces."""
    findings: List[ContainerFinding] = []
    pod_spec = spec.get("spec", {}) or {}

    host_checks = [
        ("hostNetwork", "host network namespace", "TA0009"),
        ("hostPID", "host PID namespace", "TA0005"),
        ("hostIPC", "host IPC namespace", "TA0005"),
    ]
    for key, desc, mitre_t in host_checks:
        if pod_spec.get(key) is True:
            findings.append(ContainerFinding(
                rule_id=f"K8S-HOST-{key.upper()}",
                severity="high",
                title=f"Host {desc} shared",
                description=f"{kind}/{name} shares the host {desc}.",
                resource_type=kind,
                resource_name=name,
                evidence=f"spec.{key}: true",
                remediation=f"Set {key}: false or remove the field entirely.",
                cwe="CWE-250",
                mitre_attack=[mitre_t],
            ))
    return findings


def check_volume_mounts(spec: dict, kind: str, name: str) -> List[ContainerFinding]:
    """Detect dangerous volume mounts (docker socket, host root, /proc)."""
    findings: List[ContainerFinding] = []
    pod_spec = spec.get("spec", {}) or {}
    volumes = pod_spec.get("volumes", []) or []
    dangerous_paths = {
        "/var/run/docker.sock": "Docker socket mount enables full host control.",
        "/proc": "Proc mount exposes host process and kernel information.",
        "/sys": "Sysfs mount allows hardware and kernel parameter modification.",
        "/etc/shadow": "Shadow file exposure enables credential harvesting.",
        "/etc/kubernetes": "Kube config exposure enables cluster takeover.",
        "/": "Root filesystem mount provides unrestricted host access.",
    }

    mount_vols = {v.get("name"): v for v in volumes if isinstance(v, dict)}
    containers = pod_spec.get("containers", []) or []
    for container in containers:
        for vol_mount in container.get("volumeMounts", []) or []:
            vol_name = vol_mount.get("name", "")
            mount_path = vol_mount.get("mountPath", "")
            vol_def = mount_vols.get(vol_name, {})
            host_path = (vol_def.get("hostPath", {}) or {}).get("path", "")

            for danger_path, risk_desc in dangerous_paths.items():
                if mount_path.startswith(danger_path) or host_path == danger_path:
                    findings.append(ContainerFinding(
                        rule_id="K8S-VOL-01",
                        severity="critical" if danger_path in ("/", "/var/run/docker.sock") else "high",
                        title=f"Dangerous volume mount: {danger_path}",
                        description=f"Container '{container.get('name', '?')}' mounts {danger_path} ({risk_desc})",
                        resource_type=kind,
                        resource_name=name,
                        evidence=f"mountPath={mount_path} hostPath={host_path or 'N/A'}",
                        remediation="Remove the volume mount. Use projected service account tokens or secrets instead.",
                        cwe="CWE-250",
                        mitre_attack=["TA0005", "TA0009"],
                    ))
    return findings


def check_image_config(img_str: str, container_name: str, kind: str, res_name: str) -> List[ContainerFinding]:
    """Validate container image reference for tag policy compliance."""
    findings: List[ContainerFinding] = []
    img_lower = img_str.lower()

    if ":latest" in img_lower or (":" not in img_str and "@" not in img_str):
        findings.append(ContainerFinding(
            rule_id="IMG-TAG-01",
            severity="medium",
            title="Image uses 'latest' tag or no tag",
            description=f"Container '{container_name}' in {kind}/{res_name} uses image '{img_str}'.",
            resource_type=kind,
            resource_name=res_name,
            evidence=f"image: {img_str}",
            remediation="Pin images to a specific digest (@sha256:...) or semantic version tag.",
            cwe="CWE-1104",
        ))
    if img_lower.startswith("localhost") or img_lower.startswith("127.0.0.1"):
        findings.append(ContainerFinding(
            rule_id="IMG-LOCAL-01",
            severity="low",
            title="Local-only image reference",
            description=f"Image references localhost — may not be available on other nodes.",
            resource_type=kind,
            resource_name=res_name,
            evidence=f"image: {img_str}",
            remediation="Use an internal container registry accessible to all cluster nodes.",
        ))
    return findings


def analyze_manifest(content: str, path: str) -> ContainerReport:
    """Parse and validate a Kubernetes manifest file."""
    report = ContainerReport(target=path, timestamp=datetime.utcnow().isoformat() + "Z")
    doc_or_docs = yaml.safe_load_all(content) if isinstance(content, str) else content
    for doc in doc_or_docs:
        if not isinstance(doc, dict):
            continue
        kind = doc.get("kind", "Unknown")
        meta = doc.get("metadata", {}) or {}
        name = meta.get("name", "unnamed")
        report.resources_checked += 1

        spec = doc.get("spec", {}) or {}

        # Only apply pod-level checks to kinds that contain pod specs
        effective_spec: dict = {}
        if kind in ("Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"):
            effective_spec = spec.get("template", {}).get("spec", {}) if kind != "Pod" else spec
            report.findings.extend(check_run_as_root({"spec": effective_spec}, kind, name))
            report.findings.extend(check_privileged_mode({"spec": effective_spec}, kind, name))
            report.findings.extend(check_host_namespace({"spec": effective_spec}, kind, name))
            report.findings.extend(check_volume_mounts({"spec": effective_spec}, kind, name))
            for container in (effective_spec.get("containers", []) or []):
                img = container.get("image", "")
                if img:
                    report.findings.extend(check_image_config(img, container.get("name", "?"), kind, name))

        # RBAC checks
        if kind in ("ClusterRole", "Role"):
            rules = doc.get("rules", []) or []
            for rule in rules:
                verbs = rule.get("verbs", []) or []
                resources = rule.get("resources", []) or []
                if "*" in verbs and ("*" in resources or "pods" in resources or "secrets" in resources):
                    report.findings.append(ContainerFinding(
                        rule_id="RBAC-WILD-01",
                        severity="high",
                        title="Overly permissive RBAC binding",
                        description=f"{kind} '{name}' grants wildcard verbs on sensitive resources.",
                        resource_type=kind,
                        resource_name=name,
                        evidence=f"verbs={verbs} resources={resources}",
                        remediation="Replace wildcard verbs with least-privilege equivalents (get, list, watch only).",
                        cwe="CWE-269",
                        mitre_attack=["TA0003"],
                    ))

        # Service account token auto-mount
        if kind in ("Pod", "Deployment"):
            sa = effective_spec.get("serviceAccountName", "") or effective_spec.get("serviceAccount", "")
            automount = effective_spec.get("automountServiceAccountToken")
            if automount is not False and sa and "default" not in sa.lower():
                report.findings.append(ContainerFinding(
                    rule_id="SA-AUTO-01",
                    severity="medium",
                    title="Service account token auto-mounted",
                    description=f"Service account '{sa or 'default'}' token is auto-mounted into the pod.",
                    resource_type=kind,
                    resource_name=name,
                    evidence="automountServiceAccountToken not set to false",
                    remediation="Set automountServiceAccountToken: false unless the pod requires API access.",
                    cwe="CWE-250",
                ))

    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NIGHTFANG Container & Kubernetes Manifest Analyzer",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("path", help="Path to K8s manifest YAML file or directory")
    parser.add_argument("-o", "--output", metavar="PATH", help="Save JSON report")
    args = parser.parse_args()

    if os.path.isdir(args.path):
        targets = [os.path.join(r, f) for r, _, fs in os.walk(args.path) for f in fs if f.endswith((".yaml", ".yml"))]
    else:
        targets = [args.path]

    combined = ContainerReport(target=args.path, timestamp=datetime.utcnow().isoformat() + "Z")
    for tp in targets:
        try:
            with open(tp, encoding="utf-8", errors="replace") as fh:
                content = fh.read()
            report = analyze_manifest(content, tp)
            combined.findings.extend(report.findings)
            combined.resources_checked += report.resources_checked
        except OSError as exc:
            print(f"[!] Could not read {tp}: {exc}", file=sys.stderr)

    print(f"\n  [*] Checked {combined.resources_checked} resource(s) across {len(targets)} file(s)")
    print(f"  [*] Found {len(combined.findings)} issue(s)\n")
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    for f in sorted(combined.findings, key=lambda x: sev_order.get(x.severity, 9)):
        print(f"  [{f.severity.upper():>9s}] {f.title}")
        print(f"           {f.resource_type}/{f.resource_name}: {f.evidence[:100]}")

    if args.output:
        out_dir = os.path.dirname(args.output) or "."
        os.makedirs(out_dir, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(combined.to_json())
        print(f"\n  [*] Report saved: {args.output}")

    crit_high = sum(1 for f in combined.findings if f.severity in ("critical", "high"))
    return 2 if crit_high > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
