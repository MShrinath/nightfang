#!/usr/bin/env python3
"""Ingest PentestingEverything methodology into nightfang references/methodology/.

Distills each domain's README + nested sub-topics + vulnerability classes into a
single per-domain markdown file that nightfang agents can load as procedural knowledge.
"""
import os

PE = os.environ.get(
    "NIGHTFANG_PENTESTING_EVERYTHING",
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "..", "refs", "PentestingEverything"
    )
)
OUT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "references", "methodology"
)

DOMAIN_MAP = {
    "Web Application Pentesting": "web",
    "API Pentesting": "api",
    "Active Directory Pentesting": "active-directory",
    "Cloud Pentesting": "cloud",
    "Container & Kubernetes  Assessment": "container",
    "CI-CD Pentesting": "cicd",
    "Mobile Pentesting": "mobile",
    "IoT Pentesting": "iot",
    "OSINT": "osint",
    "LLM Security Assessment": "ai-llm",
    "MCP Security Assessment": "ai-mcp",
    "Threat Modeling": "threat-modeling",
    "Secure Code Review": "code-review",
    "Network Pentesting": "network",
    "Wi-Fi Pentesting": "wireless",
    "Forensic": "forensics",
    "Infrastucture Security": "infrastructure",
    "Firewall Penetration": "firewall",
    "BlockChain Pentesting": "blockchain",
    "Phishing Assessment": "phishing",
    "A2A Security Assessment": "agentic-ai",
    "DevSecOps": "devsecops",
    "Configuration Review": "config-review",
    "Thick Client Pentesting": "thick-client",
}


def read_md(path, limit=3000):
    if not os.path.exists(path):
        return ""
    with open(path, encoding="utf-8", errors="replace") as f:
        txt = f.read()
    return txt[:limit]


def list_vuln_classes(domain_dir):
    vdir = os.path.join(domain_dir, "Vulnerabilities")
    if not os.path.isdir(vdir):
        return []
    out = []
    for entry in sorted(os.listdir(vdir)):
        full = os.path.join(vdir, entry)
        if not os.path.isdir(full):
            continue
        readme = os.path.join(full, "README.md")
        desc = ""
        if os.path.exists(readme):
            with open(readme, encoding="utf-8", errors="replace") as f:
                lines = [l.strip() for l in f.read().splitlines() if l.strip()]
            para = []
            for l in lines:
                if l.startswith("#"):
                    if para:
                        break
                    continue
                para.append(l)
                if len(para) >= 2:
                    break
            desc = " ".join(para)[:220]
        out.append((entry, desc))
    return out


def list_subdirs(dpath, skip={"References", "Vulnerabilities", "src", "static", "scripts"}):
    out = []
    for entry in sorted(os.listdir(dpath)):
        full = os.path.join(dpath, entry)
        if entry in skip or not os.path.isdir(full):
            continue
        out.append(entry)
    return out


def main():
    os.makedirs(OUT, exist_ok=True)
    index = []
    for d, slug in DOMAIN_MAP.items():
        dpath = os.path.join(PE, d)
        if not os.path.isdir(dpath):
            continue
        readme = os.path.join(dpath, "README.md")
        if not os.path.exists(readme):
            for alt in ("Readme.md", "readme.md", "Fundamentals.md", "Methodology.md"):
                if os.path.exists(os.path.join(dpath, alt)):
                    readme = os.path.join(dpath, alt)
                    break
        vulns = list_vuln_classes(dpath)
        subs = list_subdirs(dpath)

        out_path = os.path.join(OUT, f"{slug}.md")
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(f"# Methodology: {slug}\n\n")
            f.write(
                f"Source: [PentestingEverything/{d}](https://github.com/m14r41/PentestingEverything/tree/main/{d.replace(' ', '%20')})\n\n"
            )
            f.write("---\n\n")
            body = read_md(readme, 2500)
            if body.strip():
                f.write(body)
                f.write("\n\n---\n\n")
            if subs:
                f.write("## Sub-Topics\n\n")
                for s in subs:
                    f.write(f"- {s}\n")
                f.write("\n")
            if vulns:
                f.write("## Vulnerability Classes Covered\n\n")
                f.write("| Class | Description |\n|-------|-------------|\n")
                for name, desc in vulns:
                    f.write(f"| {name} | {desc} |\n")
                f.write("\n")
        index.append((slug, d, len(vulns), len(subs), os.path.basename(out_path)))
        print(f"OK {slug}: {len(vulns)} vuln classes, {len(subs)} sub-topics")

    with open(os.path.join(OUT, "INDEX.md"), "w", encoding="utf-8") as f:
        f.write("# Methodology Index\n\n")
        f.write(
            "Ingested from [PentestingEverything](https://github.com/m14r41/PentestingEverything) "
            "into nightfang as agent-procedural knowledge. Re-run `scripts/ingest_methodology.py` to refresh.\n\n"
        )
        f.write("| Slug | Source Domain | Vuln Classes | Sub-Topics | File |\n|------|---------------|--------------|------------|------|\n")
        for slug, d, n, s, fn in index:
            f.write(f"| {slug} | {d} | {n} | {s} | {fn} |\n")
    print(f"INDEX written: {len(index)} domains")


if __name__ == "__main__":
    main()
