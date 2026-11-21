#!/usr/bin/env python3
"""
Cryptographic Implementation & Configuration Analyzer
Inspects certificate files, key parameters, and cipher suites for weaknesses.
Read-only — never attempts man-in-the-middle or active interception.
"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import socket
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional


@dataclass
class CryptoFinding:
    rule_id: str
    severity: str
    title: str
    description: str
    component: str
    evidence: str
    remediation: str
    cwe: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id, "severity": self.severity,
            "title": self.title, "description": self.description[:300],
            "component": self.component, "evidence": self.evidence[:400],
            "remediation": self.remediation, "cwe": self.cwe,
        }


WEAK_CURVES = {"secp112r1", "secp112r2", "secp128r1", "secp128r2",
               "secp160k1", "secp160r1", "secp160r2", "secp192k1",
               "brainpoolP160r1", "brainpoolP160t1"}
MIN_RSA_KEY_BITS = 2048


def _load_cert(path: str) -> Optional[object]:
    """Load an X.509 certificate from PEM or DER file."""
    try:
        import cryptography.x509 as x509_mod
    except ImportError:
        print("[!] cryptography package required for certificate parsing.", file=sys.stderr)
        return None
    with open(path, "rb") as fh:
        raw = fh.read()
    for loader in (x509_mod.load_pem_x509_certificate, x509_mod.load_der_x509_certificate):
        try:
            return loader(raw)
        except Exception:
            pass
    return None


def analyze_cert(cert_path: str) -> List[CryptoFinding]:
    """Analyze a single certificate file for cryptographic weaknesses."""
    findings: List[CryptoFinding] = []
    cert = _load_cert(cert_path)
    if cert is None:
        findings.append(CryptoFinding(
            rule_id="CRT-PARSE-01", severity="informational",
            title="Certificate parse failure",
            description=f"Could not parse {cert_path} as PEM or DER certificate.",
            component="parser", evidence=cert_path,
            remediation="Verify the file is a valid X.509 certificate.",
        ))
        return findings

    subject_cn = next((rdn.value for rdn in cert.subject if rdn.key_name == "commonName"), "")
    san_values: List[str] = []
    try:
        import cryptography.x509 as x509_mod
        san_ext = cert.extensions.get_extension_for_class(x509_mod.SubjectAlternativeName)
        san_values = san_ext.value.get_values_for_type(x509_mod.DNSName)
    except Exception:
        pass

    pub_key = cert.public_key()
    key_type = type(pub_key).__name__

    # RSA key size check
    if "RsaEncryption" in key_type or "RSAPublicKey" in key_type:
        try:
            key_size = pub_key.key_size
            if key_size < MIN_RSA_KEY_BITS:
                findings.append(CryptoFinding(
                    rule_id="KEY-RSA-01", severity="high",
                    title=f"RSA key too small ({key_size} bits)",
                    description="RSA keys below 2048 bits are vulnerable to factoring attacks.",
                    component="public_key", evidence=f"{key_type}: {key_size} bits",
                    remediation="Re-issue certificate with at least 2048-bit RSA key.",
                    cwe="CWE-326",
                ))
        except Exception:
            pass

    # EC curve check
    if "EcPublicKey" in key_type:
        try:
            curve_name = pub_key.curve.name.lower()
            if curve_name in WEAK_CURVES:
                findings.append(CryptoFinding(
                    rule_id="KEY-EC-01", severity="critical",
                    title=f"Weak EC curve: {curve_name}",
                    description="Weak elliptic curves provide insufficient security margins.",
                    component="public_key", evidence=f"Curve: {curve_name}",
                    remediation="Use P-256 (secp256r1), P-384, or Ed25519 instead.",
                    cwe="CWE-327",
                ))
        except Exception:
            pass

    sig_alg = getattr(cert.signature_algorithm_oid, "_name", str(cert.signature_algorithm_oid))
    sig_lower = sig_alg.lower()
    if any(w in sig_lower for w in ("md2", "md5")):
        findings.append(CryptoFinding(
            rule_id="SIG-HASH-01", severity="high",
            title=f"Weak signature hash: {sig_alg}",
            description="MD2/MD5 based signatures are cryptographically broken.",
            component="signature_algorithm", evidence=sig_alg,
            remediation="Re-issue using SHA-256 or stronger (SHA-384, SHA-512).",
            cwe="CWE-328",
        ))
    elif "sha1" in sig_lower and "sha128" not in sig_lower:
        findings.append(CryptoFinding(
            rule_id="SIG-HASH-02", severity="medium",
            title="SHA-1 signature detected",
            description="SHA-1 has known collision vulnerabilities; deprecated but still accepted by some CAs.",
            component="signature_algorithm", evidence=sig_alg,
            remediation="Re-issue certificate with SHA-256+ signature algorithm.",
            cwe="CWE-328",
        ))

    issuer_cn = next((rdn.value for rdn in cert.issuer if rdn.key_name == "commonName"), "")
    if subject_cn == issuer_cn and subject_cn:
        findings.append(CryptoFinding(
            rule_id="CRT-SELF-01", severity="low",
            title="Self-signed certificate",
            description="Certificate issuer matches subject — likely self-signed.",
            component="subject/issuer", evidence=f"Subject CN={subject_cn}, Issuer CN={issuer_cn}",
            remediation="Use a CA-signed certificate for production environments.",
            cwe="CWE-295",
        ))

    now = datetime.now(timezone.utc)
    nva = cert.not_valid_after_utc
    if nva < now:
        findings.append(CryptoFinding(
            rule_id="CRT-EXP-01", severity="high",
            title="Certificate expired",
            description=f"Certificate expired on {nva.isoformat()}.",
            component="validity", evidence=f"Not After: {nva}",
            remediation="Renew the certificate immediately.",
            cwe="CWE-295",
        ))
    elif (nva - now).days < 30:
        findings.append(CryptoFinding(
            rule_id="CRT-EXP-02", severity="medium",
            title="Certificate expiring within 30 days",
            description=f"Expires on {nva.isoformat()}.",
            component="validity", evidence=f"{(nva - now).days} days remaining",
            remediation="Initiate certificate renewal process before expiration.",
            cwe="CWE-295",
        ))

    return findings


def scan_cipher_suite(url: str) -> List[CryptoFinding]:
    """Perform a non-invasive TLS handshake probe against a URL host."""
    findings: List[CryptoFinding] = []
    weak_ciphers = {
        "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_RSA_WITH_RC4_128_SHA",
        "TLS_RSA_WITH_RC4_128_MD5", "TLS_RSA_WITH_NULL_SHA",
        "TLS_RSA_WITH_NULL_MD5", "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_RC4_128_SHA", "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    }
    try:
        host = url.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cipher_info = ssock.cipher()
                if cipher_info:
                    cipher_name = cipher_info[0]
                    if cipher_name in weak_ciphers:
                        findings.append(CryptoFinding(
                            rule_id="TLS-CIPHER-01", severity="high",
                            title=f"Weak cipher negotiated: {cipher_name}",
                            description="Negotiated cipher suite has known weaknesses.",
                            component="tls_handshake", evidence=cipher_name,
                            remediation="Disable weak cipher suites on the server; prefer AES-GCM and CHACHA20.",
                            cwe="CWE-327",
                        ))
    except Exception as exc:
        findings.append(CryptoFinding(
            rule_id="TLS-SCAN-01", severity="informational",
            title="TLS probe skipped",
            description=str(exc)[:200],
            component="tls_probe", evidence=url,
            remediation="Manual review recommended.",
        ))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NIGHTFANG Cryptographic Configuration Analyzer",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("target", help="Path to .crt/.pem/.der file or https:// URL")
    parser.add_argument("-o", "--output", metavar="PATH", help="Save JSON report")
    args = parser.parse_args()

    target = args.target
    timestamp = datetime.utcnow().isoformat() + "Z"

    if target.startswith(("http://", "https://")):
        findings = scan_cipher_suite(target)
        target_type = "url"
    elif os.path.isfile(target) and any(target.lower().endswith(ext) for ext in (".crt", ".pem", ".der", ".cer")):
        findings = analyze_cert(target)
        target_type = "certificate"
    else:
        print(f"[!] Unrecognized target type: {target}", file=sys.stderr)
        return 2

    print(f"\n  [*] Analyzed {len(findings)} issue(s) for {target}\n")
    for f in sorted(findings, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.severity, 9)):
        print(f"  [{f.severity.upper():>9s}] {f.title}")
        print(f"           {f.component}: {f.evidence[:100]}")

    if args.output:
        out_dir = os.path.dirname(args.output) or "."
        os.makedirs(out_dir, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump({"target": target, "type": target_type, "timestamp": timestamp,
                       "findings_count": len(findings),
                       "findings": [f.to_dict() for f in findings]},
                      fh, indent=2)
        print(f"\n  [*] Report saved: {args.output}", file=sys.stderr)

    crit_high = sum(1 for f in findings if f.severity in ("critical", "high"))
    return 2 if crit_high > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
