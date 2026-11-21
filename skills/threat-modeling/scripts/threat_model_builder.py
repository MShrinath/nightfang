#!/usr/bin/env python3
"""
Threat Modelling Helper — builds data-flow diagrams (DFDs) from component
descriptions and runs automated STRIDE/LINDDUN risk classification.
Outputs structured threat inventory compatible with Microsoft Threat Modeling Tool JSON.
Read-only: no network probes, no service interaction.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional


@dataclass
class TrustBoundary:
    name: str
    from_zone: str
    to_zone: str
    direction: str = "both"  # in, out, both
    encryption: bool = False
    authentication: bool = False
    notes: str = ""


@dataclass
class DataFlow:
    source: str
    destination: str
    protocol: str
    data_type: str
    is_trusted: bool = True
    boundaries_crossed: List[str] = field(default_factory=list)
    threats: List[str] = field(default_factory=list)

    def classify_stride(self) -> List[str]:
        """Apply STRIDE taxonomy to derive potential threats."""
        threats: List[str] = []
        if not self.is_trusted:
            threats.append("Spoofing")
        if self.protocol.lower() in ("http", "ftp", "telnet"):
            threats.append("Tampering")
        if any(kw in self.data_type.lower() for kw in ("pii", "password", "secret", "token", "key")):
            threats.append("Information Disclosure")
        if self.protocol.lower() in ("telnet", "ftp"):
            threats.append("Repudiation")
        if not self.is_trusted and len(self.boundaries_crossed) > 0:
            threats.append("Denial of Service")
        if self.protocol.lower() in ("smtp", "imap", "pop3", "http"):
            threats.append("Elevation of Privilege")
        return sorted(set(threats))


@dataclass
class SystemComponent:
    name: str
    process: bool = False
    store: bool = False
    external: bool = False
    description: str = ""
    trust_level: str = "untrusted"  # trusted, untrusted, external
    privileges: List[str] = field(default_factory=list)


@dataclass
class ThreatModel:
    system_name: str
    version: str
    timestamp: str
    components: List[SystemComponent] = field(default_factory=list)
    flows: List[DataFlow] = field(default_factory=list)
    boundaries: List[TrustBoundary] = field(default_factory=list)
    summary: Dict = field(default_factory=dict)

    def add_component(self, c: SystemComponent) -> None:
        self.components.append(c)

    def add_flow(self, f: DataFlow) -> None:
        self.flows.append(f)

    def add_boundary(self, b: TrustBoundary) -> None:
        self.boundaries.append(b)

    def classifypathogens_and_classify(self) -> Dict[str, int]:
        counts: Dict[str, int] = {"Spoofing": 0, "Tampering": 0,
                                   "Information Disclosure": 0, "Repudiation": 0,
                                   "Denial of Service": 0, "Elevation of Privilege": 0}
        for flow in self.flows:
            for t in flow.classify_stride():
                counts[t] = counts.get(t, 0) + 1
        return counts

    def to_microsoft_json(self) -> dict:
        model = {
            "version": self.version,
            "system": self.system_name,
            "created": self.timestamp,
            "externalEntities": [],
            "processes": [],
            "stores": [],
            "trustBoundaries": [],
            "dataStores": [],
            "flows": [],
        }
        for comp in self.components:
            if comp.external:
                model["externalEntities"].append({"label": comp.name, "notes": comp.description})
            elif comp.process:
                model["processes"].append({
                    "label": comp.name, "notes": comp.description,
                    "outOfScope": False,
                })
            elif comp.store:
                model["dataStores"].append({"label": comp.name, "notes": comp.description})
            else:
                model["processes"].append({"label": comp.name, "notes": comp.description})

        for b in self.boundaries:
            model["trustBoundaries"].append({
                "source": b.from_zone, "destination": b.to_zone,
                "notes": b.notes or "",
            })

        for fl in self.flows:
            model["flows"].append({
                "from": fl.source, "to": fl.destination,
                "protocol": fl.protocol,
                "description": fl.data_type,
                "isEncrypted": fl.boundaries_crossed,
            })
        return model


def parse_threatmodel_json(input_path: str) -> Optional[ThreatModel]:
    """Load an existing threat-model JSON file (Microsoft TMT format)."""
    try:
        with open(input_path, encoding="utf-8", errors="replace") as fh:
            raw = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[!] Failed to load model: {exc}", file=sys.stderr)
        return None

    model = ThreatModel(
        system_name=raw.get("system", os.path.basename(input_path)),
        version=raw.get("version", "1.0"),
        timestamp=datetime.utcnow().isoformat() + "Z",
    )
    for ent in raw.get("externalEntities", []):
        model.add_component(SystemComponent(name=ent["label"], external=True, description=ent.get("notes", "")))
    for proc in raw.get("processes", []):
        if proc.get("outOfScope"):
            continue
        model.add_component(SystemComponent(name=proc["label"], process=True, description=proc.get("notes", "")))
    for store in raw.get("dataStores", []):
        model.add_component(SystemComponent(name=store["label"], store=True, description=store.get("notes", "")))
    for tb in raw.get("trustBoundaries", []):
        model.add_boundary(TrustBoundary(name=f"TB-{len(model.boundaries)+1}",
                                          from_zone=tb.get("source", ""),
                                          to_zone=tb.get("destination", "")))
    for fl in raw.get("flows", []):
        model.add_flow(DataFlow(
            source=fl.get("from", ""), destination=fl.get("to", ""),
            protocol=fl.get("protocol", ""), data_type=fl.get("description", ""),
        ))
    return model


def interactive_builder_prompt() -> ThreatModel:
    """Prompt the user interactively for a simple threat model via CLI args."""
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--system", required=True)
    parser.add_argument("--component", action="append", default=[], help="NAME[:type][;desc]")
    parser.add_argument("--flow", action="append", default=[], help="SRC->DST|PROTOCOL|DATATYPE")
    args, _ = parser.parse_known_args()

    model = ThreatModel(system_name=args.system, version="1.0", timestamp=datetime.utcnow().isoformat() + "Z")
    for comp_spec in args.component:
        parts = comp_spec.split(":", 1)
        name = parts[0]
        kind = parts[1] if len(parts) > 1 else "process"
        desc = ""
        if ";" in name:
            name, desc = name.split(";", 1)
        flags = {"external": False, "process": True, "store": False}
        if kind in ("ext", "external"):
            flags = {"external": True, "process": False, "store": False}
        elif kind in ("store", "datastore"):
            flags = {"external": False, "process": False, "store": True}
        model.add_component(SystemComponent(name=name, **flags, description=desc))

    for fl in args.flow:
        try:
            src_dst, proto, dtype = fl.split("|", 2)
            src, dst = src_dst.split("->", 1)
            model.add_flow(DataFlow(source=src.strip(), destination=dst.strip(),
                                    protocol=proto.strip(), data_type=dtype.strip()))
        except ValueError:
            pass
    return model


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NIGHTFANG Threat Modelling Helper (STRIDE/LINDDUN)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("input", nargs="?", help="Path to existing threat-model JSON (optional)")
    parser.add_argument("-o", "--output", metavar="PATH", help="Save results as JSON")
    parser.add_argument("--interact", action="store_true", help="Interactive builder mode (uses CLI flags)")
    args = parser.parse_args()

    if args.interact or not args.input:
        model = interactive_builder_prompt()
    else:
        model = parse_threatmodel_json(args.input)
        if not model:
            return 2

    counts = model.classifypathogens_and_classify()
    model.summary = {"threat_counts_by_stride": counts, "components": len(model.components),
                     "flows": len(model.flows), "boundaries": len(model.boundaries)}

    print(f"\n  [*] System : {model.system_name}")
    print(f"  [*] Components: {len(model.components)} | Flows: {len(model.flows)} | Boundaries: {len(model.boundaries)}")
    print(f"  [*] STRIDE risk summary:\n")
    for k, v in sorted(counts.items(), key=lambda x: -x[1]):
        bar = "#" * v if v else "-"
        print(f"      {k:<24} {v:>3d}  {bar}")

    output_data = model.to_microsoft_json()
    output_data["summary"] = model.summary
    print(json.dumps(output_data, indent=2))

    if args.output:
        out_dir = os.path.dirname(args.output) or "."
        os.makedirs(out_dir, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(output_data, fh, indent=2)
        print(f"\n  [*] Saved: {args.output}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
