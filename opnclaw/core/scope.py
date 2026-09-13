"""Scope validation and enforcement."""
import ipaddress
import re
from typing import List, Optional, Tuple
from dataclasses import dataclass
from urllib.parse import urlparse

from .config import ScopeConfig


@dataclass
class ValidationResult:
    allowed: bool
    reason: str
    matched_rule: Optional[str] = None


class ScopeValidator:
    """Validates targets against engagement scope definitions."""
    
    def __init__(self, scope_config: ScopeConfig):
        self.scope = scope_config
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Pre-compile domain, IP, and URL patterns for fast matching."""
        self.in_scope_domains = self._compile_domain_patterns(self.scope.in_scope.get('domains', []))
        self.out_scope_domains = self._compile_domain_patterns(self.scope.out_of_scope.get('domains', []))
        
        self.in_scope_ips = self._compile_ip_patterns(self.scope.in_scope.get('ips', []))
        self.out_scope_ips = self._compile_ip_patterns(self.scope.out_of_scope.get('ips', []))
        
        self.in_scope_urls = self._compile_url_patterns(self.scope.in_scope.get('urls', []))
        self.out_scope_urls = self._compile_url_patterns(self.scope.out_of_scope.get('urls', []))
        
        self.allowed_ports = self._parse_ports(self.scope.in_scope.get('ports', []))
    
    def _compile_domain_patterns(self, domains: List[str]) -> List[re.Pattern]:
        patterns = []
        for domain in domains:
            domain = domain.lower().strip()
            if domain.startswith('*.'):
                # Wildcard subdomain: *.example.com matches sub.example.com but not example.com
                pattern = domain[2:].replace('.', r'\.')
                patterns.append(re.compile(rf'^[^.]+\.{pattern}$'))
            else:
                # Exact match
                pattern = domain.replace('.', r'\.')
                patterns.append(re.compile(rf'^{pattern}$'))
        return patterns
    
    def _compile_ip_patterns(self, ips: List[str]) -> List:
        patterns = []
        for ip_spec in ips:
            ip_spec = ip_spec.strip()
            if '/' in ip_spec:
                # CIDR
                patterns.append(ipaddress.ip_network(ip_spec, strict=False))
            elif '-' in ip_spec:
                # Range
                start, end = ip_spec.split('-', 1)
                patterns.append(('range', ipaddress.ip_address(start.strip()), ipaddress.ip_address(end.strip())))
            else:
                # Single IP
                patterns.append(ipaddress.ip_address(ip_spec))
        return patterns
    
    def _compile_url_patterns(self, urls: List[str]) -> List[re.Pattern]:
        patterns = []
        for url in urls:
            url = url.strip()
            # Convert glob-like patterns to regex
            regex = url.replace('.', r'\.').replace('*', '.*')
            patterns.append(re.compile(regex, re.IGNORECASE))
        return patterns
    
    def _parse_ports(self, ports: List[str]) -> set:
        allowed = set()
        for port_spec in ports:
            for part in port_spec.split(','):
                part = part.strip()
                if '-' in part:
                    start, end = map(int, part.split('-'))
                    allowed.update(range(start, end + 1))
                else:
                    allowed.add(int(part))
        return allowed
    
    def _match_domain(self, domain: str, patterns: List[re.Pattern]) -> bool:
        domain = domain.lower().strip()
        for pattern in patterns:
            if pattern.match(domain):
                return True
        return False
    
    def _match_ip(self, ip_str: str, patterns: List) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        
        for pattern in patterns:
            if isinstance(pattern, ipaddress.IPv4Network) or isinstance(pattern, ipaddress.IPv6Network):
                if ip in pattern:
                    return True
            elif isinstance(pattern, tuple) and pattern[0] == 'range':
                if pattern[1] <= ip <= pattern[2]:
                    return True
            elif isinstance(pattern, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                if ip == pattern:
                    return True
        return False
    
    def _match_url(self, url: str, patterns: List[re.Pattern]) -> bool:
        for pattern in patterns:
            if pattern.match(url):
                return True
        return False
    
    def validate_target(self, target: str, port: Optional[int] = None) -> ValidationResult:
        """
        Validate a target (domain, IP, or URL) against scope.
        Returns ValidationResult with allowed status and reason.
        """
        # Parse target
        parsed = urlparse(target if '://' in target else f'http://{target}')
        hostname = parsed.hostname or target
        target_port = port or parsed.port
        
        # Check out-of-scope first (explicit exclusions take precedence)
        if self._match_domain(hostname, self.out_scope_domains):
            return ValidationResult(False, f"Domain {hostname} explicitly out of scope", "out_of_scope_domain")
        
        if self._match_ip(hostname, self.out_scope_ips):
            return ValidationResult(False, f"IP {hostname} explicitly out of scope", "out_of_scope_ip")
        
        if self._match_url(target, self.out_scope_urls):
            return ValidationResult(False, f"URL {target} explicitly out of scope", "out_of_scope_url")
        
        # Check in-scope
        domain_allowed = self._match_domain(hostname, self.in_scope_domains)
        ip_allowed = self._match_ip(hostname, self.in_scope_ips)
        url_allowed = self._match_url(target, self.in_scope_urls)
        
        if not (domain_allowed or ip_allowed or url_allowed):
            return ValidationResult(False, f"Target {target} not in scope", "not_in_scope")
        
        # Check port if specified
        if target_port and self.allowed_ports and target_port not in self.allowed_ports:
            return ValidationResult(False, f"Port {target_port} not in allowed ports", "port_not_allowed")
        
        matched = []
        if domain_allowed: matched.append("domain")
        if ip_allowed: matched.append("ip")
        if url_allowed: matched.append("url")
        
        return ValidationResult(True, f"Target allowed via: {', '.join(matched)}", "+".join(matched))
    
    def get_scope_summary(self) -> dict:
        """Return a summary of scope for reporting."""
        return {
            'in_scope_domains': self.scope.in_scope.get('domains', []),
            'in_scope_ips': self.scope.in_scope.get('ips', []),
            'in_scope_urls': self.scope.in_scope.get('urls', []),
            'allowed_ports': sorted(self.allowed_ports),
            'out_of_scope_domains': self.scope.out_of_scope.get('domains', []),
            'out_of_scope_ips': self.scope.out_of_scope.get('ips', []),
            'out_of_scope_urls': self.scope.out_of_scope.get('urls', []),
            'rules_of_engagement': self.scope.rules_of_engagement
        }