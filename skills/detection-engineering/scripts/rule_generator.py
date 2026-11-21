#!/usr/bin/env python3
"""
Detection Engineering Rule Generator — produces YARA rules from file samples and
Sigma rules from log/event patterns. Rules are syntactically validated before
emission. Read-only; does not deploy rules into SIEM/EDR.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional


@dataclass
class DetectionRule:
    rule_type: str  # yara, sigma
    name: str
    severity: str
    description: str
    rule_text: str
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    cwe_id: str = ""
    mitre_tactic: str = ""
    mitre_technique: str = ""

    def save(self, path: str) -> None:
        ext = ".yar" if self.rule_type == "yara" else ".yaml"
        out_path = path if path.endswith(ext) else f"{path}{ext}"
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(self.render())
        print(f"  [+] Saved {self.rule_type.upper()} rule: {out_path}")

    def render(self) -> str:
        if self.rule_type == "yara":
            return self.rule_text
        return self._render_sigma()

    def _render_sigma(self) -> str:
        lines = [
            "title: " + self.name,
            "status: test",
            f"severity: {self.severity}",
            f"description: {self.description}",
        ]
        if self.tags:
            lines.append("tags: " + " ".join(f"'{t}'" for t in self.tags))
        if self.references:
            lines.append("references:")
            for ref in self.references:
                lines.append(f"  - {ref}")
        if self.cwe_id:
            lines.append(f"cpe: Application.{self.cwe_id.replace('CWE-', '')}")
        lines.extend([
            "logsource:",
            "  category: process_creation",
            "  product: windows",
            "detection:",
            "  selection:",
            "    image|endswith: .exe",
            "  condition: selection",
        ])
        return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# YARA rule generation helpers
# ---------------------------------------------------------------------------

def _escape_yara(s: str) -> str:
    """Escape a string for safe inclusion inside a YARA hex/text rule."""
    return s.encode("utf-8", errors="replace").hex()


def generate_yara_from_sample(sample_path: str, rule_name: str,
                               tag: str = "malware", min_match: int = 4) -> Optional[DetectionRule]:
    """Generate a YARA rule from byte-offset hotspots in a binary sample."""
    try:
        with open(sample_path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        print(f"[!] Could not read sample: {exc}", file=sys.stderr)
        return None

    if len(data) > 50 * 1024 * 1024:  # cap at 50 MiB
        data = data[:50 * 1024 * 1024]

    # Extract printable strings >= min_match length
    strings_list: List[tuple] = []
    current: List[int] = []
    for i, b in enumerate(data):
        if 32 <= b <= 126:
            current.append(i)
        else:
            if len(current) >= min_match:
                s = bytes(data[j] for j in current).decode("ascii", errors="replace")
                strings_list.append((s, current[0], i - 1))
            current = []
    if len(current) >= min_match:
        s = bytes(data[j] for j in current).decode("ascii", errors="replace")
        strings_list.append((s, current[0], len(data)))

    if not strings_list:
        return None

    # Pick top-N longest unique strings as rule conditions
    selected = sorted(strings_list, key=lambda x: len(x[0]), reverse=True)[:8]
    text_conditions = []
    for s, start, end in selected:
        escaped = s.replace("\\", "\\\\").replace('"', '\\"')
        text_conditions.append(f'    "$str_{hashlib.md5(s.encode()).hexdigest()[:6]}" = "{escaped}"')

    rule_body = "\n".join(text_conditions)
    rule_text = f'''rule {rule_name}
{{
    meta:
        description = "Auto-generated detection rule for {os.path.basename(sample_path)}"
        date = "{datetime.utcnow().strftime("%Y-%m-%d")}"
        hash_sha256 = "{hashlib.sha256(data).hexdigest()}"
    strings:
{rule_body}
    condition:
        any of them
}}
'''
    return DetectionRule(
        rule_type="yara", name=rule_name, severity="high",
        description=f"YARA signature derived from strings in {sample_path}",
        rule_text=rule_text, tags=[tag],
        cwe_id="", mitre_tactic="Execution", mitre_technique="T1059",
    )


def generate_yara_string_constant(name: str, constant_hex: str, comment: str = "") -> DetectionRule:
    """Create a simple YARA rule matching a raw hex constant (e.g. shellcode sig)."""
    clean = re.sub(r"[^0-9a-fA-F]", "", constant_hex)
    rule_text = f'''rule {name}
{{
    meta:
        description = "{comment or 'Signature-based YARA rule'}"
    strings:
        $sig = {{ {clean} }}
    condition:
        $sig
}}
'''
    return DetectionRule(
        rule_type="yara", name=name, severity="high",
        description=comment or f"Hex signature match: {name}",
        rule_text=rule_text, tags=["signature"],
        mitre_tactic="Execution", mitre_technique="T1059",
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NIGHTFANG Detection Engineering Rule Generator",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    p_sample = sub.add_parser("sample", help="Generate YARA rule from a binary sample")
    p_sample.add_argument("sample", help="Path to binary sample file")
    p_sample.add_argument("--name", required=True, help="YARA rule name")
    p_sample.add_argument("--tag", default="malware", help="Rule tag")
    p_sample.add_argument("-o", "--output-dir", default=".", help="Output directory for .yar files")

    p_hex = sub.add_parser("hex", help="Generate YARA rule from a hex signature string")
    p_hex.add_argument("--name", required=True, help="YARA rule name")
    p_hex.add_argument("hex_string", help="Hex-encoded signature (no spaces/newlines)")
    p_hex.add_argument("--comment", default="", help="Rule description")
    p_hex.add_argument("-o", "--output-dir", default=".", help="Output directory for .yar files")

    p_sigma = sub.add_parser("sigma", help="Generate a Sigma rule skeleton")
    p_sigma.add_argument("--name", required=True, help="Rule title")
    p_sigma.add_argument("--description", required=True, help="One-line description")
    p_sigma.add_argument("--severity", choices=["info", "low", "medium", "high", "critical"], default="high")
    p_sigma.add_argument("--tag", action="append", default=[], help="MITRE tag (repeatable)")
    p_sigma.add_argument("--reference", action="append", default=[], help="Reference URL (repeatable)")
    p_sigma.add_argument("--cwe", default="", help="CWE id (e.g. CWE-79)")
    p_sigma.add_argument("-o", "--output-dir", default=".", help="Output directory for .yaml files")

    args = parser.parse_args()

    if args.mode == "sample":
        rule = generate_yara_from_sample(args.sample, args.name, tag=args.tag)
        if not rule:
            print("[!] No valid strings extracted — sample may be too small or binary-only.", file=sys.stderr)
            return 2
        os.makedirs(args.output_dir, exist_ok=True)
        rule.save(os.path.join(args.output_dir, args.name))

    elif args.mode == "hex":
        rule = generate_yara_string_constant(args.name, args.hex_string, args.comment)
        os.makedirs(args.output_dir, exist_ok=True)
        rule.save(os.path.join(args.output_dir, args.name))

    elif args.mode == "sigma":
        rule = DetectionRule(
            rule_type="sigma", name=args.name, severity=args.severity,
            description=args.description, rule_text="",
            tags=args.tag, references=args.reference, cwe_id=args.cwe,
            mitre_tactic="Execution", mitre_technique="T1059",
        )
        os.makedirs(args.output_dir, exist_ok=True)
        rule.save(os.path.join(args.output_dir, args.name))

    print(f"\n  [*] Rule generation complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
