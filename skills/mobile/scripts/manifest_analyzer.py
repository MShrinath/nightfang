#!/usr/bin/env python3
"""
Mobile App Manifest & Configuration Analyzer
Extracts security-relevant configuration from Android (AndroidManifest.xml)
and iOS (Info.plist / Entitlements) app package configurations. Read-only.
"""
from __future__ import annotations

import argparse
import os
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class MobileFinding:
    rule_id: str
    severity: str
    title: str
    description: str
    component: str  # manifest_key, permission, activity, etc.
    evidence: str
    remediation: str
    cwe: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "description": self.description[:300],
            "component": self.component,
            "evidence": self.evidence[:400],
            "remediation": self.remediation,
            "cwe": self.cwe,
        }


@dataclass
class MobileReport:
    target: str
    timestamp: str
    platform: str  # android, ios, unknown
    findings: List[MobileFinding] = field(default_factory=list)
    parsed_keys: int = 0

    def add(self, f: MobileFinding) -> None:
        self.findings.append(f)
        self.parsed_keys += 1

    def to_json(self, indent: int = 2) -> str:
        return '''\
{
  "target": %r,
  "timestamp": %r,
  "platform": %r,
  "findings_count": %d,
  "parsed_keys": %d,
  "findings": %s
}''' % (
            self.target, self.timestamp, self.platform,
            len(self.findings), self.parsed_keys,
            __import__('json').dumps([f.to_dict() for f in self.findings], indent=indent),
        )


ANDROID_NS = "http://schemas.android.com/apk/res/android"
NSMAP = {"android": ANDROID_NS}


def _attr(elem: ET.Element, name: str) -> Optional[str]:
    """Get an attribute value handling both qualified and unqualified names."""
    for prefix in ("", ANDROID_NS, "android"):
        key = f"{{{prefix}}}{name}" if prefix else name
        val = elem.get(key)
        if val is not None:
            return val
    return None


def analyze_android_manifest(manifest_path: str) -> MobileReport:
    """Parse AndroidManifest.xml and extract security findings."""
    report = MobileReport(target=manifest_path, timestamp=datetime.utcnow().isoformat() + "Z", platform="android")

    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
    except (ET.ParseError, OSError) as exc:
        report.findings.append(MobileFinding(
            rule_id="AM-PARSE-01",
            severity="informational",
            title="Manifest parse failure",
            description=str(exc)[:200],
            component="xml_parser",
            evidence=manifest_path,
            remediation="Ensure the APK/AAB was decompiled properly with apktool or equivalent.",
        ))
        return report

    app = root.find("application") or root.find(f"{{{ANDROID_NS}}}application")
    if app is None:
        report.findings.append(MobileFinding(
            rule_id="AM-STRUCT-01",
            severity="medium",
            title="Missing <application> element",
            description="Root-level <application> tag not found in manifest.",
            component="structure",
            evidence="No <application> element",
            remediation="Verify manifest integrity; a valid Android app must have an <application> element.",
            cwe="CWE-1121",
        ))
        return report

    # debuggable flag
    debuggable = _attr(app, "debuggable")
    if debuggable == "true":
        report.add(MobileFinding(
            rule_id="AM-SEC-01",
            severity="high",
            title="App marked debuggable",
            description="Android:debuggable=true allows remote debugging and memory inspection on device.",
            component="application.debuggable",
            evidence="android:debuggable='true'",
            remediation="Set android:debuggable='false' or remove the attribute in production builds.",
            cwe="CWE-489",
        ))

    # allowBackup
    allow_backup = _attr(app, "allowBackup")
    if allow_backup == "true":
        report.add(MobileFinding(
            rule_id="AM-SEC-02",
            severity="medium",
            title="Backup enabled (allowBackup=true)",
            description="App data can be extracted via adb backup or cloud restore attacks.",
            component="application.allowBackup",
            evidence="android:allowBackup='true'",
            remediation="Set android:allowBackup='false' unless cloud sync is intentionally designed.",
            cwe="CWE-922",
        ))

    # allowClearUserData — informational only
    clear_data = _attr(app, "allowClearUserData")
    if clear_data == "true":
        report.add(MobileFinding(
            rule_id="AM-SEC-03",
            severity="low",
            title="clearUserData allowed",
            description="Explicit clearUserData policy may indicate sensitive data is not properly scoped.",
            component="application.clearUserData",
            evidence="android:allowClearUserData='true'",
            remediation="Review if user data lifecycle matches threat model expectations.",
        ))

    # networkSecurityConfig — check for cleartext traffic override
    net_sec = _attr(app, "networkSecurityConfig")
    has_network_security = net_sec is not None
    if not has_network_security:
        report.add(MobileFinding(
            rule_id="AM-SEC-04",
            severity="medium",
            title="No networkSecurityConfig defined",
            description="App does not declare a network security configuration; HTTP traffic may be permitted.",
            component="application.networkSecurityConfig",
            evidence="Attribute missing from <application>",
            remediation="Add an android:networkSecurityConfig pointing to a config that enforces TLS 1.2+.",
            cwe="CWE-319",
        ))

    # permissions
    uses_perms = root.findall("uses-permission") or root.findall(f"{{{ANDROID_NS}}}uses-permission")
    dangerous_perms = {
        "android.permission.INTERNET": False,
        "android.permission.ACCESS_FINE_LOCATION": True,
        "android.permission.ACCESS_COARSE_LOCATION": True,
        "android.permission.CAMERA": True,
        "android.permission.RECORD_AUDIO": True,
        "android.permission.READ_CONTACTS": True,
        "android.permission.WRITE_CONTACTS": True,
        "android.permission.READ_PHONE_STATE": True,
        "android.permission.SEND_SMS": True,
        "android.permission.RECEIVE_SMS": True,
        "android.permission.READ_EXTERNAL_STORAGE": True,
        "android.permission.WRITE_EXTERNAL_STORAGE": True,
        "android.permission.READ_CALENDAR": True,
        "android.permission.WRITE_CALENDAR": True,
        "android.permission.BODY_SENSORS": True,
        "android.permission.ACCESS_BACKGROUND_LOCATION": True,
        "android.permission.GET_ACCOUNTS": True,
        "android.permission.USE_FINGERPRINT": True,
        "android.permission.USE_BIOMETRIC": True,
        "android.permission.RECEIVE_BOOT_COMPLETED": True,
        "android.permission.FOREGROUND_SERVICE": True,
    }
    for perm_elem in uses_perms:
        perm_name = (_attr(perm_elem, "name") or "").strip()
        if perm_name in dangerous_perms:
            sev = "high" if dangerous_perms[perm_name] else "low"
            desc = "Sensitive personal data access" if dangerous_perms[perm_name] else "Broad system permission"
            report.add(MobileFinding(
                rule_id=f"AM-PERM-{perm_name.split('.')[-1].upper()}",
                severity=sev,
                title=f"Permission declared: {perm_name}",
                description=desc,
                component="uses-permission",
                evidence=perm_name,
                remediation=f"Remove '{perm_name}' if not required by core functionality. Apply runtime permission prompts per platform guidelines.",
                cwe="CWE-276",
            ))

    # activities with export
    for activity in root.findall(".//activity") + root.findall(f".//{{{ANDROID_NS}}}activity"):
        exported = _attr(activity, "exported")
        name = _attr(activity, "name") or activity.get("name", "?")
        if exported == "true" and "Activity" in name:
            report.add(MobileFinding(
                rule_id="AM-EXPORT-01",
                severity="medium",
                title=f"Exported activity: {name}",
                description="Exported Activity can be launched by other apps, risking intent injection.",
                component=f"activity.{name}",
                evidence="android:exported='true'",
                remediation="Set exported='false' unless the activity must be accessible from other applications.",
                cwe="CWE-916",
            ))

    # providers with export
    for provider in root.findall(".//provider") + root.findall(f".//{{{ANDROID_NS}}}provider"):
        exported = _attr(provider, "exported")
        name = _attr(provider, "name") or provider.get("name", "?")
        if exported == "true":
            report.add(MobileFinding(
                rule_id="AM-EXPORT-02",
                severity="high",
                title=f"Exported content provider: {name}",
                description="Exported ContentProvider may expose database contents to other apps.",
                component=f"provider.{name}",
                evidence="android:exported='true'",
                remediation="Set exported='false' and use a ContentProviderQueryFilter or authority-based restrictions.",
                cwe="CWE-916",
            ))

    # receivers with export
    for receiver in root.findall(".//receiver") + root.findall(f".//{{{ANDROID_NS}}}receiver"):
        exported = _attr(receiver, "exported")
        name = _attr(receiver, "name") or receiver.get("name", "?")
        if exported == "true":
            report.add(MobileFinding(
                rule_id="AM-EXPORT-03",
                severity="medium",
                title=f"Exported broadcast receiver: {name}",
                description="Exported BroadcastReceiver receives broadcasts from any app.",
                component=f"receiver.{name}",
                evidence="android:exported='true'",
                remediation="Set exported='false' unless the receiver handles system broadcasts intentionally.",
                cwe="CWE-916",
            ))

    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NIGHTFANG Mobile Manifest Security Analyzer",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("path", help="Path to AndroidManifest.xml (or directory containing it)")
    parser.add_argument("-o", "--output", metavar="PATH", help="Save JSON report")
    args = parser.parse_args()

    target = args.path
    if os.path.isdir(target):
        manifest_candidates = [os.path.join(r, f) for r, _, fs in os.walk(target) if f == "AndroidManifest.xml"]
        if not manifest_candidates:
            print("[!] No AndroidManifest.xml found in directory tree.", file=sys.stderr)
            return 2
        manifests = manifest_candidates
    else:
        manifests = [target]

    combined = MobileReport(target=args.path, timestamp=datetime.utcnow().isoformat() + "Z", platform="android")
    for mp in manifests:
        rep = analyze_android_manifest(mp)
        combined.findings.extend(rep.findings)
        combined.parsed_keys += rep.parsed_keys

    print(f"\n  [*] Analyzed {len(manifests)} manifest(s) — {len(combined.findings)} finding(s)\n")
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    for f in sorted(combined.findings, key=lambda x: sev_order.get(x.severity, 9)):
        print(f"  [{f.severity.upper():>9s}] {f.title}")
        print(f"           {f.component}: {f.evidence[:100]}")

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
