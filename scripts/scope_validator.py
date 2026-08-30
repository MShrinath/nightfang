#!/usr/bin/env python3
"""
OPENCLAW / HERMES — Scope Validator Utility
Validates whether target domains, IPs, URLs, and ports are strictly within authorized engagement scope.
"""

import sys
import ipaddress
import urllib.parse
import fnmatch
import yaml
from pathlib import Path

class ScopeValidator:
    def __init__(self, config_path: str):
        with open(config_path, "r", encoding="utf-8") as f:
            self.config = yaml.safe_load(f)
        
        self.in_scope = self.config.get("scope", {}).get("in_scope", {})
        self.out_of_scope = self.config.get("scope", {}).get("out_of_scope", {})
        
        self.allowed_domains = self.in_scope.get("domains", [])
        self.allowed_ips = [ipaddress.ip_network(ip) for ip in self.in_scope.get("ips", [])]
        self.allowed_urls = self.in_scope.get("urls", [])
        
        self.excluded_domains = self.out_of_scope.get("domains", [])
        self.excluded_ips = [ipaddress.ip_network(ip) for ip in self.out_of_scope.get("ips", [])]
        self.excluded_urls = self.out_of_scope.get("urls", [])

    def is_domain_in_scope(self, domain: str) -> bool:
        domain = domain.lower().strip()
        
        # Check explicit exclusions first
        for exc in self.excluded_domains:
            if fnmatch.fnmatch(domain, exc.lower()):
                return False
                
        # Check inclusions
        for inc in self.allowed_domains:
            if fnmatch.fnmatch(domain, inc.lower()):
                return True
        return False

    def is_ip_in_scope(self, ip_str: str) -> bool:
        try:
            target_ip = ipaddress.ip_address(ip_str.strip())
        except ValueError:
            return False
            
        for exc_net in self.excluded_ips:
            if target_ip in exc_net:
                return False
                
        for inc_net in self.allowed_ips:
            if target_ip in inc_net:
                return True
        return False

    def is_url_in_scope(self, url: str) -> bool:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname or ""
        
        # Check domain/IP boundary
        if not (self.is_domain_in_scope(hostname) or self.is_ip_in_scope(hostname)):
            return False
            
        for exc in self.excluded_urls:
            if fnmatch.fnmatch(url, exc):
                return False
                
        return True

    def validate_target(self, target: str) -> bool:
        if target.startswith("http://") or target.startswith("https://"):
            return self.is_url_in_scope(target)
        elif any(c.isalpha() for c in target):
            return self.is_domain_in_scope(target)
        else:
            return self.is_ip_in_scope(target)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python scope_validator.py <engagement_config.yaml> <target>")
        sys.exit(1)
        
    config_file = sys.argv[1]
    test_target = sys.argv[2]
    
    validator = ScopeValidator(config_file)
    result = validator.validate_target(test_target)
    
    if result:
        print(f"[+] TARGET IN-SCOPE: {test_target}")
        sys.exit(0)
    else:
        print(f"[-] TARGET OUT-OF-SCOPE: {test_target}")
        sys.exit(2)
