from pydantic import BaseModel
from typing import List, Optional
import ipaddress
from loguru import logger

class ScopeDefinition(BaseModel):
    domains: List[str]
    ip_ranges: List[str]
    wildcards: List[str]

    def is_in_scope(self, target: str) -> bool:
        """Check if a target is within the defined scope"""
        try:
            # Check if target is an IP
            ip = ipaddress.ip_address(target)
            return any(
                ip in ipaddress.ip_network(range)
                for range in self.ip_ranges
            )
        except ValueError:
            # Check if target is a domain
            return any(
                target.endswith(domain) for domain in self.domains
            ) or any(
                target.endswith(wild.lstrip('*.')) for wild in self.wildcards
            )