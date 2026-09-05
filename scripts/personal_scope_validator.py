#!/usr/bin/env python3
"""
AEGIS Personal Scope Validator
Extends HERMES scope validator with operator-specific rules and learned boundaries
"""

import sys
import os
import ipaddress
import urllib.parse
import fnmatch
from pathlib import Path
from typing import List, Dict, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
from env_loader import load_config, load_env

load_env()


class PersonalScopeValidator:
    """Extended scope validator with AEGIS personal rules"""
    
    def __init__(self, config_path: str = "config/personal_engagement.yaml"):
        self.config = load_config(config_path)
        self.hermes_config = load_config("config/engagement_template.yaml")
        
        # Merge scopes (personal overrides framework)
        self.scope = self._merge_scopes()
        
        # Compile patterns
        self._compile_patterns()
        
        # Load personal memory for learned boundaries
        self.learned_boundaries = self._load_learned_boundaries()
    
    def _merge_scopes(self) -> Dict:
        """Merge HERMES and AEGIS scopes, personal takes precedence"""
        hermes_scope = self.hermes_config.get("scope", {})
        aegis_scope = self.config.get("scope", {})
        
        merged = {}
        for key in ["in_scope", "out_of_scope"]:
            hermes_part = hermes_scope.get(key, {})
            aegis_part = aegis_scope.get(key, {})
            
            merged[key] = {}
            for subkey in ["domains", "ips", "urls", "ports"]:
                hermes_list = hermes_part.get(subkey, [])
                aegis_list = aegis_part.get(subkey, [])
                # AEGIS overrides, but include HERMES as fallback
                merged[key][subkey] = aegis_list if aegis_list else hermes_list
            
            # Notes - combine
            hermes_notes = hermes_part.get("notes", [])
            aegis_notes = aegis_part.get("notes", [])
            merged[key]["notes"] = aegis_notes + hermes_notes
        
        return merged
    
    def _compile_patterns(self):
        """Compile all patterns for fast matching"""
        in_scope = self.scope.get("in_scope", {})
        out_scope = self.scope.get("out_of_scope", {})
        
        # In-scope patterns
        self.allowed_domains = [p.lower() for p in in_scope.get("domains", [])]
        self.allowed_ips = [ipaddress.ip_network(ip) for ip in in_scope.get("ips", [])]
        self.allowed_urls = in_scope.get("urls", [])
        self.allowed_ports = self._parse_ports(in_scope.get("ports", []))
        
        # Out-of-scope patterns
        self.excluded_domains = [p.lower() for p in out_scope.get("domains", [])]
        self.excluded_ips = [ipaddress.ip_network(ip) for ip in out_scope.get("ips", [])]
        self.excluded_urls = out_scope.get("urls", [])
        
        # Personal exclusions (learned)
        self.personal_exclusions = self.learned_boundaries.get("exclusions", [])
    
    def _parse_ports(self, port_strings: List[str]) -> set:
        """Parse port strings like '80,443,8080-8090' into set of ints"""
        ports = set()
        for ps in port_strings:
            for part in ps.split(","):
                part = part.strip()
                if "-" in part:
                    start, end = map(int, part.split("-"))
                    ports.update(range(start, end + 1))
                else:
                    ports.add(int(part))
        return ports
    
    def _load_learned_boundaries(self) -> Dict:
        """Load learned scope boundaries from PERSONAL_MEMORY.md"""
        # In practice, parse PERSONAL_MEMORY.md
        # For now, return defaults
        return {
            "exclusions": [],
            "third_party_domains": [
                "*.cloudflare.com",
                "*.amazonaws.com",
                "*.azure.com",
                "*.googleapis.com",
                "*.akamai.net",
                "*.fastly.net"
            ],
            "sensitive_paths": [
                "/admin/purge",
                "/admin/delete",
                "/admin/reset",
                "/payment",
                "/billing",
                "/checkout"
            ]
        }
    
    def is_domain_in_scope(self, domain: str) -> Tuple[bool, str]:
        """Check if domain is in scope with detailed reason"""
        domain = domain.lower().strip()
        
        # Check personal exclusions first
        for excl in self.personal_exclusions:
            if fnmatch.fnmatch(domain, excl.lower()):
                return False, f"Personal exclusion: {excl}"
        
        # Check third-party domains
        for tp in self.learned_boundaries.get("third_party_domains", []):
            if fnmatch.fnmatch(domain, tp.lower()):
                return False, f"Third-party domain: {tp}"
        
        # Check explicit exclusions
        for exc in self.excluded_domains:
            if fnmatch.fnmatch(domain, exc):
                return False, f"Explicit exclusion: {exc}"
        
        # Check inclusions
        for inc in self.allowed_domains:
            if fnmatch.fnmatch(domain, inc):
                return True, f"Matched inclusion: {inc}"
        
        return False, "No matching inclusion pattern"
    
    def is_ip_in_scope(self, ip_str: str) -> Tuple[bool, str]:
        """Check if IP is in scope with detailed reason"""
        try:
            target_ip = ipaddress.ip_address(ip_str.strip())
        except ValueError:
            return False, "Invalid IP address"
        
        # Check explicit exclusions
        for exc_net in self.excluded_ips:
            if target_ip in exc_net:
                return False, f"Explicit IP exclusion: {exc_net}"
        
        # Check inclusions
        for inc_net in self.allowed_ips:
            if target_ip in inc_net:
                return True, f"Matched IP inclusion: {inc_net}"
        
        return False, "No matching IP inclusion"
    
    def is_url_in_scope(self, url: str) -> Tuple[bool, str]:
        """Check if URL is in scope with detailed reason"""
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname or ""
        path = parsed.path or "/"
        
        # Check host first
        domain_ok, domain_reason = self.is_domain_in_scope(hostname)
        if not domain_ok:
            # Try IP
            ip_ok, ip_reason = self.is_ip_in_scope(hostname)
            if not ip_ok:
                return False, f"Host out of scope: {domain_reason}"
        
        # Check sensitive paths
        for sensitive in self.learned_boundaries.get("sensitive_paths", []):
            if fnmatch.fnmatch(path, sensitive + "*"):
                return False, f"Sensitive path: {sensitive}"
        
        # Check explicit URL exclusions
        for exc in self.excluded_urls:
            if fnmatch.fnmatch(url, exc):
                return False, f"URL exclusion: {exc}"
        
        # Check URL inclusions
        for inc in self.allowed_urls:
            if fnmatch.fnmatch(url, inc):
                return True, f"Matched URL inclusion: {inc}"
        
        return True, "Host in scope, no URL exclusion"
    
    def is_port_allowed(self, port: int) -> Tuple[bool, str]:
        """Check if port is allowed"""
        if port in self.allowed_ports:
            return True, f"Port {port} in allowed list"
        return False, f"Port {port} not in allowed ports: {sorted(self.allowed_ports)}"
    
    def validate_target(self, target: str) -> Tuple[bool, str]:
        """Comprehensive target validation"""
        if target.startswith(("http://", "https://")):
            return self.is_url_in_scope(target)
        elif any(c.isalpha() for c in target):
            return self.is_domain_in_scope(target)
        else:
            return self.is_ip_in_scope(target)
    
    def validate_scan_target(self, target: str, port: int) -> Tuple[bool, str]:
        """Validate target + port combination for scanning"""
        target_ok, target_reason = self.validate_target(target)
        if not target_ok:
            return False, target_reason
        
        port_ok, port_reason = self.is_port_allowed(port)
        if not port_ok:
            return False, port_reason
        
        return True, f"Valid: {target}:{port}"
    
    def get_scope_summary(self) -> Dict:
        """Get human-readable scope summary"""
        in_scope = self.scope.get("in_scope", {})
        out_scope = self.scope.get("out_of_scope", {})
        
        return {
            "in_scope": {
                "domains": in_scope.get("domains", []),
                "ip_ranges": in_scope.get("ips", []),
                "urls": in_scope.get("urls", []),
                "ports": sorted(self.allowed_ports)
            },
            "out_of_scope": {
                "domains": out_scope.get("domains", []),
                "ip_ranges": out_scope.get("ips", []),
                "urls": out_scope.get("urls", []),
                "notes": out_scope.get("notes", [])
            },
            "learned_boundaries": {
                "third_party_domains": self.learned_boundaries.get("third_party_domains", []),
                "sensitive_paths": self.learned_boundaries.get("sensitive_paths", [])
            }
        }
    
    def check_third_party_risk(self, target: str) -> Dict:
        """Check if target resolves to third-party infrastructure"""
        # In practice, would do DNS resolution and ASN lookup
        # For now, check against known patterns
        
        third_party_patterns = [
            "*.s3.amazonaws.com",
            "*.cloudfront.net",
            "*.azureedge.net",
            "*.googleusercontent.com",
            "*.akamaized.net",
            "*.fastly.net"
        ]
        
        for pattern in third_party_patterns:
            if fnmatch.fnmatch(target.lower(), pattern.lower()):
                return {
                    "is_third_party": True,
                    "provider": pattern.split(".")[1] if "." in pattern else "unknown",
                    "pattern": pattern,
                    "warning": "Target resolves to shared infrastructure. Verify testing only affects your tenant."
                }
        
        return {"is_third_party": False}


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="AEGIS Personal Scope Validator")
    parser.add_argument("target", nargs="?", help="Target to validate")
    parser.add_argument("--port", type=int, help="Port to validate with target")
    parser.add_argument("--config", default="config/personal_engagement.yaml", help="Config file")
    parser.add_argument("--summary", action="store_true", help="Show scope summary")
    parser.add_argument("--check-third-party", action="store_true", help="Check third-party risk")
    
    args = parser.parse_args()
    
    validator = PersonalScopeValidator(args.config)
    
    if args.summary:
        summary = validator.get_scope_summary()
        print(json.dumps(summary, indent=2))
        return
    
    if not args.target:
        parser.print_help()
        return
    
    if args.port:
        ok, reason = validator.validate_scan_target(args.target, args.port)
    else:
        ok, reason = validator.validate_target(args.target)
    
    if args.check_third_party:
        risk = validator.check_third_party_risk(args.target)
        print(f"Third-party risk: {json.dumps(risk, indent=2)}")
    
    print(f"{'[+] IN-SCOPE' if ok else '[-] OUT-OF-SCOPE'}: {args.target}")
    print(f"    Reason: {reason}")
    
    sys.exit(0 if ok else 2)


if __name__ == "__main__":
    import json
    main()